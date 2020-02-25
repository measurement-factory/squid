/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 90    Storage Manager Client-Side Interface */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncCbdataCalls.h"
#include "base/CodeContext.h"
#include "event.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "mime_header.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_swapin.h"
#include "StoreClient.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

/*
 * NOTE: 'Header' refers to the swapfile metadata header.
 *   'OBJHeader' refers to the object header, with canonical
 *   processed object headers (which may derive from FTP/HTTP etc
 *   upstream protocols
 *       'Body' refers to the swapfile body, which is the full
 *        HTTP reply (including HTTP headers and body).
 */
static StoreIOState::STRCB storeClientReadBody;
static StoreIOState::STRCB storeClientReadHeader;
static void storeClientCopy2(StoreEntry * e, store_client * sc);
static bool CheckQuickAbortIsReasonable(StoreEntry * entry);

CBDATA_CLASS_INIT(store_client);

/* StoreClient */

bool
StoreClient::onCollapsingPath() const
{
    if (!Config.onoff.collapsed_forwarding)
        return false;

    if (!Config.accessList.collapsedForwardingAccess)
        return true;

    ACLFilledChecklist checklist(Config.accessList.collapsedForwardingAccess, nullptr, nullptr);
    fillChecklist(checklist);
    return checklist.fastCheck().allowed();
}

bool
StoreClient::startCollapsingOn(const StoreEntry &e, const bool doingRevalidation) const
{
    if (!e.hittingRequiresCollapsing())
        return false; // collapsing is impossible due to the entry state

    if (!onCollapsingPath())
        return false; // collapsing is impossible due to Squid configuration

    /* collapsing is possible; the caller must collapse */

    if (const auto tags = loggingTags()) {
        if (doingRevalidation)
            tags->collapsingHistory.revalidationCollapses++;
        else
            tags->collapsingHistory.otherCollapses++;
    }

    debugs(85, 5, e << " doingRevalidation=" << doingRevalidation);
    return true;
}

/* store_client */

bool
store_client::memReaderHasLowerOffset(int64_t anOffset) const
{
    return getType() == STORE_MEM_CLIENT && copyInto.offset < anOffset;
}

int
store_client::getType() const
{
    return type;
}

#if STORE_CLIENT_LIST_DEBUG
static store_client *
storeClientListSearch(const MemObject * mem, void *data)
{
    dlink_node *node;
    store_client *sc = NULL;

    for (node = mem->clients.head; node; node = node->next) {
        sc = node->data;

        if (sc->owner == data)
            return sc;
    }

    return NULL;
}

int
storeClientIsThisAClient(store_client * sc, void *someClient)
{
    return sc->owner == someClient;
}

#endif
#include "HttpRequest.h"

/* add client with fd to client list */
store_client *
storeClientListAdd(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    store_client *sc;
    assert(mem);
#if STORE_CLIENT_LIST_DEBUG

    if (storeClientListSearch(mem, data) != NULL)
        /* XXX die! */
        assert(1 == 0);
#else
    (void)data;
#endif

    sc = new store_client (e);

    mem->addClient(sc);

    return sc;
}

static void
CallbackClientSide(store_client *sc)
{
    sc->callbackClientSide();
}

void
store_client::callbackClientSide()
{
    assert(_callback.pending());

    clientSideCaller = nullptr;
    StoreIOBuffer result(copiedSize, copyInto.offset, copyInto.data);
    result.flags.error = copyInto.flags.error;

    auto temphandler = _callback.callback_handler;
    void *cbdata = _callback.callback_data;
    _callback = store_client::Callback(nullptr, nullptr);
    copyInto.data = nullptr;
    copiedSize = 0;

    if (cbdataReferenceValid(cbdata))
        temphandler(cbdata, result);

    cbdataReferenceDone(cbdata);
}

void
store_client::callback(ssize_t sz, bool error)
{
    copiedSize = (sz > 0 && !error) ? sz : 0;

    if (sz < 0 || error)
        copyInto.flags.error = 1;

    if (clientSideCaller)
        return;

    /// XXX: do not schedule if the object is going to be deleted,
    /// see storeUnregister().
    clientSideCaller = asyncCall(17, 4, "Callback", cbdataDialer(CallbackClientSide, this));
    ScheduleCallHere(clientSideCaller);
}

store_client::store_client(StoreEntry *e) :
#if STORE_CLIENT_LIST_DEBUG
    owner(cbdataReference(data)),
#endif
    entry(e),
    copiedSize(0),
    type(e->storeClientType()),
    object_ok(true)
{
    flags.disk_io_pending = false;
    ++ entry->refcount;

    if (getType() == STORE_DISK_CLIENT) {
        /* assert we'll be able to get the data we want */
        /* maybe we should open swapin_sio here */
        assert(entry->hasDisk() && !entry->swapoutFailed());
    }
}

store_client::~store_client()
{}

/* copy bytes requested by the client */
void
storeClientCopy(store_client * sc,
                StoreEntry * e,
                StoreIOBuffer copyInto,
                STCB * callback,
                void *data)
{
    assert (sc != NULL);
    sc->copy(e, copyInto,callback,data);
}

void
store_client::copy(StoreEntry * anEntry,
                   StoreIOBuffer copyRequest,
                   STCB * callback_fn,
                   void *data)
{
    assert (anEntry == entry);
    assert (callback_fn);
    assert (data);
    assert(!EBIT_TEST(entry->flags, ENTRY_ABORTED));
    debugs(90, 3, "store_client::copy: " << entry->getMD5Text() << ", from " <<
           copyRequest.offset << ", for length " <<
           (int) copyRequest.length << ", cb " << callback_fn << ", cbdata " <<
           data);

#if STORE_CLIENT_LIST_DEBUG

    assert(this == storeClientListSearch(entry->mem_obj, data));
#endif

    assert(!_callback.pending());
    /* range requests will skip into the body */
    _callback = Callback (callback_fn, cbdataReference(data));
    copyInto.data = copyRequest.data;
    copyInto.length = copyRequest.length;
    copyInto.offset = copyRequest.offset;

    static bool copying (false);
    assert (!copying);
    copying = true;
    /* we might be blocking comm reads due to readahead limits
     * now we have a new offset, trigger those reads...
     */
    entry->mem_obj->kickReads();
    copying = false;

    anEntry->lock("store_client::copy"); // see deletion note below

    storeClientCopy2(entry, this);

    // Bug 3480: This store_client object may be deleted now if, for example,
    // the client rejects the hit response copied above. Use on-stack pointers!

#if USE_ADAPTATION
    anEntry->kickProducer();
#endif
    anEntry->unlock("store_client::copy");

    // Add no code here. This object may no longer exist.
}

/// Whether there is (or will be) more entry data for us.
bool
store_client::moreToSend() const
{
    if (entry->store_status == STORE_PENDING)
        return true; // there may be more coming

    /* STORE_OK, including aborted entries: no more data is coming */

    const int64_t len = entry->objectLen();

    // If we do not know the entry length, then we have to open the swap file.
    const bool canSwapIn = entry->hasDisk();
    if (len < 0)
        return canSwapIn;

    if (copyInto.offset >= len)
        return false; // sent everything there is

    if (canSwapIn)
        return true; // if we lack prefix, we can swap it in

    // If we cannot swap in, make sure we have what we want in RAM. Otherwise,
    // scheduleRead calls scheduleDiskRead which asserts without a swap file.
    const MemObject *mem = entry->mem_obj;
    return mem &&
           mem->inmem_lo <= copyInto.offset && copyInto.offset < mem->endOffset();
}

static void
storeClientCopy2(StoreEntry * e, store_client * sc)
{
    debugs(90, 3, "storeClientCopy2: " << e->getMD5Text());
    /*
     * We used to check for ENTRY_ABORTED here.  But there were some
     * problems.  For example, we might have a slow client (or two) and
     * the peer server is reading far ahead and swapping to disk.  Even
     * if the peer aborts, we want to give the client(s)
     * everything we got before the abort condition occurred.
     */

    // TODO: optimize, immediately returning if is no data yet

    sc->doCopy(sc->entry);
}

void
store_client::doCopy(StoreEntry *anEntry)
{
    assert (anEntry == entry);
    MemObject *mem = entry->mem_obj;

    debugs(33, 5, "store_client::doCopy: co: " <<
           copyInto.offset << ", hi: " <<
           mem->endOffset());

    if (!moreToSend()) {
        /* There is no more to send! */
        debugs(33, 3, "There is no more to send!");
        callback(0);
        return;
    }

    /* Check that we actually have data */
    if (anEntry->store_status == STORE_PENDING && copyInto.offset >= mem->endOffset()) {
        debugs(90, 3, "store_client::doCopy: Waiting for more");
        return;
    }

    /*
     * Slight weirdness here.  We open a swapin file for any
     * STORE_DISK_CLIENT, even if we can copy the requested chunk
     * from memory in the next block.  We must try to open the
     * swapin file before sending any data to the client side.  If
     * we postpone the open, and then can not open the file later
     * on, the client loses big time.  Its transfer just gets cut
     * off.  Better to open it early (while the client side handler
     * is clientCacheHit) so that we can fall back to a cache miss
     * if needed.
     */

    if (STORE_DISK_CLIENT == getType() && swapin_sio == NULL) {
        if (!startSwapin())
            return; // failure
    }
    scheduleRead();
}

/// opens the swapin "file" if possible; otherwise, fail()s and returns false
bool
store_client::startSwapin()
{
    debugs(90, 3, "store_client::doCopy: Need to open swap in file");
    /* gotta open the swapin file */

    if (storeTooManyDiskFilesOpen()) {
        /* yuck -- this causes a TCP_SWAPFAIL_MISS on the client side */
        fail();
        return false;
    } else if (!flags.disk_io_pending) {
        /* Don't set store_io_pending here */
        storeSwapInStart(this);

        if (swapin_sio == NULL) {
            fail();
            return false;
        }

        return true;
    } else {
        debugs(90, DBG_IMPORTANT, "WARNING: Averted multiple fd operation (1)");
        return false;
    }
}

void
store_client::scheduleRead()
{
    MemObject *mem = entry->mem_obj;

    if (copyInto.offset >= mem->inmem_lo && copyInto.offset < mem->endOffset())
        scheduleMemRead();
    else
        scheduleDiskRead();
}

void
store_client::scheduleDiskRead()
{
    /* What the client wants is not in memory. Schedule a disk read */
    if (getType() == STORE_DISK_CLIENT) {
        // we should have called startSwapin() already
        assert(swapin_sio != NULL);
    } else if (!swapin_sio && !startSwapin()) {
        debugs(90, 3, "bailing after swapin start failure for " << *entry);
        return;
    }

    assert(!flags.disk_io_pending);

    debugs(90, 3, "reading " << *entry << " from disk");

    fileRead();
}

void
store_client::scheduleMemRead()
{
    /* What the client wants is in memory */
    /* Old style */
    debugs(90, 3, "store_client::doCopy: Copying normal from memory");
    size_t sz = entry->mem_obj->data_hdr.copy(copyInto);
    callback(sz);
}

void
store_client::fileRead()
{
    MemObject *mem = entry->mem_obj;

    assert(_callback.pending());
    assert(!flags.disk_io_pending);
    flags.disk_io_pending = true;

    if (mem->swap_hdr_sz != 0)
        if (entry->swappingOut())
            assert(mem->swapout.sio->offset() > copyInto.offset + (int64_t)mem->swap_hdr_sz);

    storeRead(swapin_sio,
              copyInto.data,
              copyInto.length,
              copyInto.offset + mem->swap_hdr_sz,
              mem->swap_hdr_sz == 0 ? storeClientReadHeader
              : storeClientReadBody,
              this);
}

void
store_client::readBody(const char *, ssize_t len)
{
    int parsed_header = 0;

    // Don't assert disk_io_pending here.. may be called by read_header
    flags.disk_io_pending = false;
    assert(_callback.pending());
    debugs(90, 3, "storeClientReadBody: len " << len << "");

    if (len < 0)
        return fail();

    const auto rep = entry->mem_obj ? &entry->mem().baseReply() : nullptr;
    if (copyInto.offset == 0 && len > 0 && rep && rep->sline.status() == Http::scNone) {
        /* Our structure ! */
        if (!entry->mem_obj->adjustableBaseReply().parseCharBuf(copyInto.data, headersEnd(copyInto.data, len))) {
            debugs(90, DBG_CRITICAL, "ERROR: Could not parse headers from on disk object");
        } else {
            parsed_header = 1;
        }
    }

    if (len > 0 && rep && entry->mem_obj->inmem_lo == 0 && entry->objectLen() <= (int64_t)Config.Store.maxInMemObjSize && Config.onoff.memory_cache_disk) {
        storeGetMemSpace(len);
        // The above may start to free our object so we need to check again
        if (entry->mem_obj->inmem_lo == 0) {
            /* Copy read data back into memory.
             * copyInto.offset includes headers, which is what mem cache needs
             */
            int64_t mem_offset = entry->mem_obj->endOffset();
            if ((copyInto.offset == mem_offset) || (parsed_header && mem_offset == rep->hdr_sz)) {
                entry->mem_obj->write(StoreIOBuffer(len, copyInto.offset, copyInto.data));
            }
        }
    }

    callback(len);
}

void
store_client::fail()
{
    object_ok = false;
    /* synchronous open failures callback from the store,
     * before startSwapin detects the failure.
     * TODO: fix this inconsistent behaviour - probably by
     * having storeSwapInStart become a callback functions,
     * not synchronous
     */

    if (_callback.pending())
        callback(0, true);
}

static void
storeClientReadHeader(void *data, const char *buf, ssize_t len, StoreIOState::Pointer)
{
    store_client *sc = (store_client *)data;
    sc->readHeader(buf, len);
}

static void
storeClientReadBody(void *data, const char *buf, ssize_t len, StoreIOState::Pointer)
{
    store_client *sc = (store_client *)data;
    sc->readBody(buf, len);
}

bool
store_client::unpackHeader(char const *buf, ssize_t len)
{
    debugs(90, 3, "store_client::unpackHeader: len " << len << "");
    assert(len >= 0);

    int swap_hdr_sz = 0;
    tlv *tlv_list = nullptr;
    try {
        StoreMetaUnpacker aBuilder(buf, len, &swap_hdr_sz);
        tlv_list = aBuilder.createStoreMeta();
    } catch (const std::exception &e) {
        debugs(90, DBG_IMPORTANT, "WARNING: failed to unpack metadata because " << e.what());
        return false;
    }
    assert(tlv_list);

    /*
     * Check the meta data and make sure we got the right object.
     */
    for (tlv *t = tlv_list; t; t = t->next) {
        if (!t->checkConsistency(entry)) {
            storeSwapTLVFree(tlv_list);
            return false;
        }
    }

    storeSwapTLVFree(tlv_list);

    assert(swap_hdr_sz >= 0);
    entry->mem_obj->swap_hdr_sz = swap_hdr_sz;
    if (entry->swap_file_sz > 0) { // collapsed hits may not know swap_file_sz
        assert(entry->swap_file_sz >= static_cast<uint64_t>(swap_hdr_sz));
        entry->mem_obj->object_sz = entry->swap_file_sz - swap_hdr_sz;
    }
    debugs(90, 5, "store_client::unpackHeader: swap_file_sz=" <<
           entry->swap_file_sz << "( " << swap_hdr_sz << " + " <<
           entry->mem_obj->object_sz << ")");
    return true;
}

void
store_client::readHeader(char const *buf, ssize_t len)
{
    MemObject *const mem = entry->mem_obj;

    assert(flags.disk_io_pending);
    flags.disk_io_pending = false;
    assert(_callback.pending());

    // abort if we fail()'d earlier
    if (!object_ok)
        return;

    if (len < 0)
        return fail();

    if (!unpackHeader(buf, len)) {
        fail();
        return;
    }

    /*
     * If our last read got some data the client wants, then give
     * it to them, otherwise schedule another read.
     */
    size_t body_sz = len - mem->swap_hdr_sz;

    if (copyInto.offset < static_cast<int64_t>(body_sz)) {
        /*
         * we have (part of) what they want
         */
        size_t copy_sz = min(copyInto.length, body_sz);
        debugs(90, 3, "storeClientReadHeader: copying " << copy_sz << " bytes of body");
        memmove(copyInto.data, copyInto.data + mem->swap_hdr_sz, copy_sz);

        readBody(copyInto.data, copy_sz);

        return;
    }

    /*
     * we don't have what the client wants, but at least we now
     * know the swap header size.
     */
    fileRead();
}

int
storeClientCopyPending(store_client * sc, StoreEntry * e, void *data)
{
#if STORE_CLIENT_LIST_DEBUG
    assert(sc == storeClientListSearch(e->mem_obj, data));
#else
    (void)data;
#endif

    assert(sc);
    assert(sc->entry == e);

    if (!sc->_callback.pending())
        return 0;

    return 1;
}

/*
 * This routine hasn't been optimised to take advantage of the
 * passed sc. Yet.
 */
int
storeUnregister(store_client * sc, StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
#if STORE_CLIENT_LIST_DEBUG
    assert(sc == storeClientListSearch(e->mem_obj, data));
#else
    (void)data;
#endif

    if (mem == NULL)
        return 0;

    debugs(90, 3, "storeUnregister: called for '" << e->getMD5Text() << "'");

    if (sc == NULL) {
        debugs(90, 3, "storeUnregister: No matching client for '" << e->getMD5Text() << "'");
        return 0;
    }

    if (mem->clientCount() == 0) {
        debugs(90, 3, "storeUnregister: Consistency failure - store client being unregistered is not in the mem object's list for '" << e->getMD5Text() << "'");
        return 0;
    }

    dlinkDelete(&sc->node, &mem->clients);
    -- mem->nclients;

    const auto swapoutFinished = e->swappedOut() || e->swapoutFailed();
    if (e->store_status == STORE_OK && !swapoutFinished)
        e->swapOut();

    if (sc->swapin_sio != NULL) {
        storeClose(sc->swapin_sio, StoreIOState::readerDone);
        sc->swapin_sio = NULL;
        ++statCounter.swap.ins;
    }

    if (sc->_callback.pending()) {
        /* callback with ssize = -1 to indicate unexpected termination */
        debugs(90, 3, "store_client for " << *e << " has a callback");
        sc->fail();
    }

#if STORE_CLIENT_LIST_DEBUG
    cbdataReferenceDone(sc->owner);

#endif

    delete sc;

    assert(e->locked());
    // An entry locked by others may be unlocked (and destructed) by others, so
    // we must lock again to safely dereference e after CheckQuickAbortIsReasonable().
    e->lock("storeUnregister");

    if (CheckQuickAbortIsReasonable(e))
        e->abort();
    else
        mem->kickReads();

#if USE_ADAPTATION
    e->kickProducer();
#endif

    e->unlock("storeUnregister");
    return 1;
}

/* Call handlers waiting for  data to be appended to E. */
void
StoreEntry::invokeHandlers()
{
    if (EBIT_TEST(flags, DELAY_SENDING)) {
        debugs(90, 3, "DELAY_SENDING is on, exiting " << *this);
        return;
    }
    if (EBIT_TEST(flags, ENTRY_FWD_HDR_WAIT)) {
        debugs(90, 3, "ENTRY_FWD_HDR_WAIT is on, exiting " << *this);
        return;
    }

    /* Commit what we can to disk, if appropriate */
    swapOut();
    int i = 0;
    store_client *sc;
    dlink_node *nx = NULL;
    dlink_node *node;

    debugs(90, 3, mem_obj->nclients << " clients; " << *this << ' ' << getMD5Text());
    /* walk the entire list looking for valid callbacks */

    const auto savedContext = CodeContext::Current();
    for (node = mem_obj->clients.head; node; node = nx) {
        sc = (store_client *)node->data;
        nx = node->next;
        ++i;

        if (!sc->_callback.pending())
            continue;

        if (sc->flags.disk_io_pending)
            continue;

        CodeContext::Reset(sc->_callback.codeContext);
        debugs(90, 3, "checking client #" << i);
        storeClientCopy2(this, sc);
    }
    CodeContext::Reset(savedContext);
}

// Does not account for remote readers/clients.
int
storePendingNClients(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    int npend = NULL == mem ? 0 : mem->nclients;
    debugs(90, 3, "storePendingNClients: returning " << npend);
    return npend;
}

/* return true if the request should be aborted */
static bool
CheckQuickAbortIsReasonable(StoreEntry * entry)
{
    assert(entry);
    debugs(90, 3, "entry=" << *entry);

    if (storePendingNClients(entry) > 0) {
        debugs(90, 3, "quick-abort? NO storePendingNClients() > 0");
        return false;
    }

    if (!shutting_down && Store::Root().transientReaders(*entry)) {
        debugs(90, 3, "quick-abort? NO still have one or more transient readers");
        return false;
    }

    if (entry->store_status != STORE_PENDING) {
        debugs(90, 3, "quick-abort? NO store_status != STORE_PENDING");
        return false;
    }

    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL)) {
        debugs(90, 3, "quick-abort? NO ENTRY_SPECIAL");
        return false;
    }

    MemObject * const mem = entry->mem_obj;
    assert(mem);
    debugs(90, 3, "mem=" << mem);

    if (mem->request && !mem->request->flags.cachable) {
        debugs(90, 3, "quick-abort? YES !mem->request->flags.cachable");
        return true;
    }

    if (EBIT_TEST(entry->flags, KEY_PRIVATE)) {
        debugs(90, 3, "quick-abort? YES KEY_PRIVATE");
        return true;
    }

    const auto &reply = mem->baseReply();

    if (reply.hdr_sz <= 0) {
        // TODO: Check whether this condition works for HTTP/0 responses.
        debugs(90, 3, "quick-abort? YES no object data received yet");
        return true;
    }

    if (Config.quickAbort.min < 0) {
        debugs(90, 3, "quick-abort? NO disabled");
        return false;
    }

    if (mem->request && mem->request->range && mem->request->getRangeOffsetLimit() < 0) {
        // the admin has configured "range_offset_limit none"
        debugs(90, 3, "quick-abort? NO admin configured range replies to full-download");
        return false;
    }

    if (reply.content_length < 0) {
        // XXX: cf.data.pre does not document what should happen in this case
        // We know that quick_abort is enabled, but no limit can be applied.
        debugs(90, 3, "quick-abort? YES unknown content length");
        return true;
    }
    const auto expectlen = reply.hdr_sz + reply.content_length;

    int64_t curlen =  mem->endOffset();

    if (curlen > expectlen) {
        debugs(90, 3, "quick-abort? YES bad content length (" << curlen << " of " << expectlen << " bytes received)");
        return true;
    }

    if ((expectlen - curlen) < (Config.quickAbort.min << 10)) {
        debugs(90, 3, "quick-abort? NO only a little more object left to receive");
        return false;
    }

    if ((expectlen - curlen) > (Config.quickAbort.max << 10)) {
        debugs(90, 3, "quick-abort? YES too much left to go");
        return true;
    }

    // XXX: This is absurd! TODO: For positives, "a/(b/c) > d" is "a*c > b*d".
    if (expectlen < 100) {
        debugs(90, 3, "quick-abort? NO avoid FPE");
        return false;
    }

    if ((curlen / (expectlen / 100)) > (Config.quickAbort.pct)) {
        debugs(90, 3, "quick-abort? NO past point of no return");
        return false;
    }

    debugs(90, 3, "quick-abort? YES default");
    return true;
}

void
store_client::dumpStats(MemBuf * output, int clientNumber) const
{
    if (_callback.pending())
        return;

    output->appendf("\tClient #%d, %p\n", clientNumber, _callback.callback_data);
    output->appendf("\t\tcopy_offset: %" PRId64 "\n", copyInto.offset);
    output->appendf("\t\tcopy_size: %" PRIuSIZE "\n", copyInto.length);
    output->append("\t\tflags:", 8);

    if (flags.disk_io_pending)
        output->append(" disk_io_pending", 16);

    output->append("\n",1);
}

bool
store_client::Callback::pending() const
{
    return callback_handler && callback_data;
}

store_client::Callback::Callback(STCB *function, void *data):
    callback_handler(function),
    callback_data(data),
    codeContext(CodeContext::Current())
{
}

#if USE_DELAY_POOLS
void
store_client::setDelayId(DelayId delay_id)
{
    delayId = delay_id;
}
#endif

