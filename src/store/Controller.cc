/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Controller */

#include "squid.h"
#include "mem_node.h"
#include "MemStore.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "store/Controller.h"
#include "store/Disks.h"
#include "store/LocalSearch.h"
#include "tools.h"
#include "Transients.h"

#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

/*
 * store_dirs_rebuilding is initialized to _1_ as a hack so that
 * storeDirWriteCleanLogs() doesn't try to do anything unless _all_
 * cache_dirs have been read.  For example, without this hack, Squid
 * will try to write clean log files if -kparse fails (becasue it
 * calls fatal()).
 */
int Store::Controller::store_dirs_rebuilding = 1;

Store::Controller::Controller() :
    swapDir(new Disks),
    memStore(NULL),
    transients(NULL)
{
    assert(!store_table);
}

Store::Controller::~Controller()
{
    delete memStore;
    delete transients;
    delete swapDir;

    if (store_table) {
        hashFreeItems(store_table, destroyStoreEntry);
        hashFreeMemory(store_table);
        store_table = nullptr;
    }
}

void
Store::Controller::init()
{
    if (Config.memShared && IamWorkerProcess()) {
        memStore = new MemStore;
        memStore->init();
    }

    swapDir->init();

    if (UsingSmp() && IamWorkerProcess() && Config.onoff.collapsed_forwarding &&
            smpAware()) {
        transients = new Transients;
        transients->init();
    }
}

void
Store::Controller::create()
{
    swapDir->create();

#if !_SQUID_WINDOWS_
    pid_t pid;
    do {
        PidStatus status;
        pid = WaitForAnyPid(status, WNOHANG);
    } while (pid > 0 || (pid < 0 && errno == EINTR));
#endif
}

void
Store::Controller::maintain()
{
    static time_t last_warn_time = 0;

    PROF_start(storeMaintainSwapSpace);
    swapDir->maintain();

    /* this should be emitted by the oversize dir, not globally */

    if (Root().currentSize() > Store::Root().maxSize()) {
        if (squid_curtime - last_warn_time > 10) {
            debugs(20, DBG_CRITICAL, "WARNING: Disk space over limit: "
                   << Store::Root().currentSize() / 1024.0 << " KB > "
                   << (Store::Root().maxSize() >> 10) << " KB");
            last_warn_time = squid_curtime;
        }
    }

    PROF_stop(storeMaintainSwapSpace);
}

void
Store::Controller::getStats(StoreInfoStats &stats) const
{
    if (memStore)
        memStore->getStats(stats);
    else {
        // move this code to a non-shared memory cache class when we have it
        stats.mem.shared = false;
        stats.mem.capacity = Config.memMaxSize;
        stats.mem.size = mem_node::StoreMemSize();
        stats.mem.count = hot_obj_count;
    }

    swapDir->getStats(stats);

    // low-level info not specific to memory or disk cache
    stats.store_entry_count = StoreEntry::inUseCount();
    stats.mem_object_count = MemObject::inUseCount();
}

void
Store::Controller::stat(StoreEntry &output) const
{
    storeAppendPrintf(&output, "Store Directory Statistics:\n");
    storeAppendPrintf(&output, "Store Entries          : %lu\n",
                      (unsigned long int)StoreEntry::inUseCount());
    storeAppendPrintf(&output, "Maximum Swap Size      : %" PRIu64 " KB\n",
                      maxSize() >> 10);
    storeAppendPrintf(&output, "Current Store Swap Size: %.2f KB\n",
                      currentSize() / 1024.0);
    storeAppendPrintf(&output, "Current Capacity       : %.2f%% used, %.2f%% free\n",
                      Math::doublePercent(currentSize(), maxSize()),
                      Math::doublePercent((maxSize() - currentSize()), maxSize()));

    if (memStore)
        memStore->stat(output);

    /* now the swapDir */
    swapDir->stat(output);
}

/* if needed, this could be taught to cache the result */
uint64_t
Store::Controller::maxSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->maxSize();
}

uint64_t
Store::Controller::minSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->minSize();
}

uint64_t
Store::Controller::currentSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->currentSize();
}

uint64_t
Store::Controller::currentCount() const
{
    /* TODO: include memory cache ? */
    return swapDir->currentCount();
}

int64_t
Store::Controller::maxObjectSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->maxObjectSize();
}

void
Store::Controller::updateLimits()
{
    swapDir->updateLimits();

    store_swap_high = (long) (((float) maxSize() *
                               (float) Config.Swap.highWaterMark) / (float) 100);
    store_swap_low = (long) (((float) maxSize() *
                              (float) Config.Swap.lowWaterMark) / (float) 100);
    store_pages_max = Config.memMaxSize / sizeof(mem_node);

    // TODO: move this into a memory cache class when we have one
    const int64_t memMax = static_cast<int64_t>(min(Config.Store.maxInMemObjSize, Config.memMaxSize));
    const int64_t disksMax = swapDir ? swapDir->maxObjectSize() : 0;
    store_maxobjsize = std::max(disksMax, memMax);
}

StoreSearch *
Store::Controller::search()
{
    // this is the only kind of search we currently support
    return NewLocalSearch();
}

void
Store::Controller::sync(void)
{
    if (memStore)
        memStore->sync();
    swapDir->sync();
}

/*
 * handle callbacks all avaliable fs'es
 */
int
Store::Controller::callback()
{
    /* This will likely double count. Thats ok. */
    PROF_start(storeDirCallback);

    /* mem cache callbacks ? */
    int result = swapDir->callback();

    PROF_stop(storeDirCallback);

    return result;
}

void
Store::Controller::referenceBusy(StoreEntry &e)
{
    // special entries do not belong to any specific Store, but are IN_MEMORY
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return;

    /* Notify the fs that we're referencing this object again */

    if (e.hasDisk())
        swapDir->reference(e);

    // Notify the memory cache that we're referencing this object again
    if (memStore && e.mem_status == IN_MEMORY)
        memStore->reference(e);

    // TODO: move this code to a non-shared memory cache class when we have it
    if (e.mem_obj) {
        if (mem_policy->Referenced)
            mem_policy->Referenced(mem_policy, &e, &e.mem_obj->repl);
    }
}

bool
Store::Controller::dereferenceIdle(StoreEntry &e, bool wantsLocalMemory)
{
    // special entries do not belong to any specific Store, but are IN_MEMORY
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return true;

    bool keepInStoreTable = false; // keep only if somebody needs it there

    /* Notify the fs that we're not referencing this object any more */

    if (e.hasDisk())
        keepInStoreTable = swapDir->dereference(e) || keepInStoreTable;

    // Notify the memory cache that we're not referencing this object any more
    if (memStore && e.mem_status == IN_MEMORY)
        keepInStoreTable = memStore->dereference(e) || keepInStoreTable;

    // TODO: move this code to a non-shared memory cache class when we have it
    if (e.mem_obj) {
        if (mem_policy->Dereferenced)
            mem_policy->Dereferenced(mem_policy, &e, &e.mem_obj->repl);
        // non-shared memory cache relies on store_table
        if (!memStore)
            keepInStoreTable = wantsLocalMemory || keepInStoreTable;
    }

    return keepInStoreTable;
}

bool
Store::Controller::markedForDeletion(const cache_key *key) const
{
    // Checking Transients should cover many, but not all cases.
    // Since we require that only StoreEntry writer must have the
    // corresponding Transients entry, there can be StoreEntries,
    // detached from Transients but still marked for deletion in
    // another storage.
    return transients && transients->markedForDeletion(key);
}

bool
Store::Controller::markedForDeletion(const StoreEntry &e) const
{
    if (transients && transients->markedForDeletion(e))
        return true;
    if (memStore && memStore->markedForDeletion(e))
        return true;
    if (swapDir && swapDir->markedForDeletion(e))
        return true;
    return false;
}

bool
Store::Controller::markedForDeletionAndAbandoned(const StoreEntry &e) const
{
    return markedForDeletion(reinterpret_cast<const cache_key*>(e.key)) &&
           transients && !transients->readers(e);
}

bool
Store::Controller::hasReadableDiskEntry(const StoreEntry &e) const
{
    return swapDir->hasReadableEntry(e);
}

StoreEntry *
Store::Controller::get(const CacheKey &cacheKey)
{
    if (StoreEntry *e = find(cacheKey)) {
        // this is not very precise: some get()s are not initiated by clients
        e->touch();
        referenceBusy(*e);
        return e;
    }
    return nullptr;
}

// TODO: partially duplicates Controller::find().
StoreEntry*
Store::Controller::intransitEntry(const CacheKey &cacheKey)
{
    if (markedForDeletion(cacheKey.key)) {
        debugs(20, 3, "ignoring marked " << storeKeyText(cacheKey.key));
        return nullptr;
    }

    if (StoreEntry *e = static_cast<StoreEntry*>(hash_lookup(store_table, cacheKey.key))) {
        if (!markedForDeletion(*e))
            return e;
    }

    if (transients)
        return transients->get(cacheKey);

    return nullptr;
}

/// Internal method to implements the guts of the Store::get() API:
/// returns an in-transit or cached object with a given key, if any.
StoreEntry *
Store::Controller::find(const CacheKey &cacheKey)
{
    debugs(20, 3, storeKeyText(cacheKey.key));

    if (markedForDeletion(cacheKey.key)) {
        debugs(20, 3, "ignoring marked " << storeKeyText(cacheKey.key));
        return nullptr;
    }

    if (StoreEntry *e = static_cast<StoreEntry*>(hash_lookup(store_table, cacheKey.key))) {
        if (!markedForDeletion(*e)) {
            // TODO: ignore and maybe handleIdleEntry() unlocked intransit entries
            // because their backing store slot may be gone already.
            debugs(20, 3, HERE << "got in-transit entry: " << *e);
            return e;
        }
    }

    // Must search transients before caches because we must sync those we find.
    if (transients) {
        if (StoreEntry *e = transients->get(cacheKey)) {
            debugs(20, 3, "got shared in-transit entry: " << *e);
            if (!e->mem_obj->smpCollapsed)
                return e;
            bool inSync = false;
            const bool found = anchorCollapsed(*e, inSync);
            if (!found || inSync)
                return e;
            assert(!e->locked()); // ensure release will destroyStoreEntry()
            e->release(); // do not let others into the same trap
            return NULL;
        }
    }

    if (memStore) {
        if (StoreEntry *e = memStore->get(cacheKey)) {
            debugs(20, 3, HERE << "got mem-cached entry: " << *e);
            return e;
        }
    }

    if (swapDir) {
        if (StoreEntry *e = swapDir->get(cacheKey)) {
            debugs(20, 3, "got disk-cached entry: " << *e);
            return e;
        }
    }

    debugs(20, 4, "cannot locate " << storeKeyText(cacheKey.key));
    return nullptr;
}

int64_t
Store::Controller::accumulateMore(StoreEntry &entry) const
{
    return swapDir ? swapDir->accumulateMore(entry) : 0;
    // The memory cache should not influence for-swapout accumulation decision.
}

void
Store::Controller::markForUnlink(StoreEntry &e)
{
    if (transients)
        transients->markForUnlink(e);
    if (memStore)
        memStore->markForUnlink(e);
    if (swapDir)
        swapDir->markForUnlink(e);
}

void
Store::Controller::unlinkByKeyIfFound(const cache_key *key)
{
    if (StoreEntry *entry = intransitEntry(CacheKey(key))) {
        assert(entry->hasTransients());
        transients->markForUnlink(*entry);
    }

    if (memStore)
        memStore->unlinkByKeyIfFound(key);
    if (swapDir)
        swapDir->unlinkByKeyIfFound(key);
}

void
Store::Controller::unlink(StoreEntry &e)
{
    if (transients)
        transients->markForUnlink(e);
    memoryUnlink(e);
    if (swapDir)
        swapDir->unlink(e);
}

// move this into [non-shared] memory cache class when we have one
/// whether e should be kept in local RAM for possible future caching
bool
Store::Controller::keepForLocalMemoryCache(StoreEntry &e) const
{
    if (!e.memoryCachable())
        return false;

    // does the current and expected size obey memory caching limits?
    assert(e.mem_obj);
    const int64_t loadedSize = e.mem_obj->endOffset();
    const int64_t expectedSize = e.mem_obj->expectedReplySize(); // may be < 0
    const int64_t ramSize = max(loadedSize, expectedSize);
    const int64_t ramLimit = min(
                                 static_cast<int64_t>(Config.memMaxSize),
                                 static_cast<int64_t>(Config.Store.maxInMemObjSize));
    return ramSize <= ramLimit;
}

void
Store::Controller::memoryOut(StoreEntry &e, const bool preserveSwappable)
{
    bool keepInLocalMemory = false;
    if (memStore)
        memStore->write(e); // leave keepInLocalMemory false
    else
        keepInLocalMemory = keepForLocalMemoryCache(e);

    debugs(20, 7, HERE << "keepInLocalMemory: " << keepInLocalMemory);

    if (!keepInLocalMemory)
        e.trimMemory(preserveSwappable);
}

void
Store::Controller::memoryUnlink(StoreEntry &e)
{
    if (memStore)
        memStore->unlink(e);
    else // TODO: move into [non-shared] memory cache class when we have one
        e.destroyMemObject();
}

void
Store::Controller::memoryDisconnect(StoreEntry &e)
{
    if (memStore)
        memStore->disconnect(e);
    // else nothing to do for non-shared memory cache
}

void
Store::Controller::transientsAbandon(StoreEntry &e)
{
    if (transients) {
        assert(e.mem_obj);
        if (e.hasTransients())
            transients->abandon(e);
    }
}

void
Store::Controller::transientsCompleteWriting(StoreEntry &e)
{
    if (transients && e.hasTransients() && transients->collapsedWriter(e))
        transients->completeWriting(e);
}

int
Store::Controller::transientReaders(const StoreEntry &e) const
{
    return (transients && e.hasTransients()) ?
           transients->readers(e) : 0;
}

void
Store::Controller::transientsDisconnect(MemObject &mem_obj)
{
    if (transients)
        transients->disconnect(mem_obj);
}

void
Store::Controller::handleIdleEntry(StoreEntry &e)
{
    bool keepInLocalMemory = false;

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL)) {
        // Icons (and cache digests?) should stay in store_table until we
        // have a dedicated storage for them (that would not purge them).
        // They are not managed [well] by any specific Store handled below.
        keepInLocalMemory = true;
    } else if (memStore) {
        // leave keepInLocalMemory false; memStore maintains its own cache
    } else {
        keepInLocalMemory = keepForLocalMemoryCache(e) && // in good shape and
                            // the local memory cache is not overflowing
                            (mem_node::InUseCount() <= store_pages_max);
    }

    // An idle, unlocked entry that only belongs to a SwapDir which controls
    // its own index, should not stay in the global store_table.
    if (!dereferenceIdle(e, keepInLocalMemory)) {
        debugs(20, 5, HERE << "destroying unlocked entry: " << &e << ' ' << e);
        destroyStoreEntry(static_cast<hash_link*>(&e));
        return;
    }

    debugs(20, 5, HERE << "keepInLocalMemory: " << keepInLocalMemory);

    // TODO: move this into [non-shared] memory cache class when we have one
    if (keepInLocalMemory) {
        e.setMemStatus(IN_MEMORY);
        e.mem_obj->unlinkRequest();
    } else {
        e.purgeMem(); // may free e
    }
}

void
Store::Controller::updateOnNotModified(StoreEntry *old, const StoreEntry &newer)
{
    /* update the old entry object */
    Must(old);
    HttpReply *oldReply = const_cast<HttpReply*>(old->getReply());
    Must(oldReply);

    const bool modified = oldReply->updateOnNotModified(newer.getReply());
    if (!old->timestampsSet() && !modified)
        return;

    /* update stored image of the old entry */

    if (memStore && old->mem_status == IN_MEMORY && !EBIT_TEST(old->flags, ENTRY_SPECIAL))
        memStore->updateHeaders(old);

    if (old->hasDisk())
        swapDir->updateHeaders(old);
}

void
Store::Controller::allowCollapsing(StoreEntry *e, const RequestFlags &reqFlags,
                                   const HttpRequestMethod &reqMethod)
{
    const KeyScope keyScope = reqFlags.refresh ? ksRevalidation : ksDefault;
    e->makePublic(keyScope); // this is needed for both local and SMP collapsing
    debugs(20, 3, "may " << (transients && e->hasTransients() ?
                "SMP-" : "locally-") << "collapse " << *e);
}

bool
Store::Controller::createTransientsEntry(StoreEntry *e, const CacheKey &cacheKey, const bool switchToReading)
{
    assert(transients);
    if (e->hasTransients())
        return true;

    bool collisionDetected = false;
    if (!transients->startWriting(e, cacheKey, collisionDetected)) {
        // a collision means that there is already transients writer
        return collisionDetected;
    }
    if (switchToReading)
        transientsCompleteWriting(*e);
    return true;
}

void
Store::Controller::syncCollapsed(const sfileno xitIndex)
{
    assert(transients);

    StoreEntry *collapsed = transients->findCollapsed(xitIndex);
    if (!collapsed) { // the entry is no longer locally active, ignore update
        debugs(20, 7, "not SMP-syncing not-transient " << xitIndex);
        return;
    }

    if (!collapsed->locked()) {
        debugs(20, 3, "will release unlocked " << *collapsed);
        // should destroy unlocked entry
        collapsed->release();
        return;
    }

    assert(collapsed->mem_obj);

    if (EBIT_TEST(collapsed->flags, ENTRY_ABORTED)) {
        debugs(20, 3, "skipping already aborted " << *collapsed);
        return;
    }

    debugs(20, 7, "syncing " << *collapsed);

    bool abortedByWriter = false;
    bool waitingToBeFreed = false;
    transients->status(*collapsed, abortedByWriter, waitingToBeFreed);

    if (waitingToBeFreed) {
        debugs(20, 3, "will release " << *collapsed << " due to waitingToBeFreed");
        collapsed->release(true); // may already be marked
    }

    if (transients->collapsedWriter(*collapsed))
        return; // readers can only change our waitingToBeFreed flag

    assert(transients->collapsedReader(*collapsed));

    if (abortedByWriter) {
        debugs(20, 3, "aborting " << *collapsed << " because its writer has aborted");
        collapsed->abort();
        return;
    }

    bool found = false;
    bool inSync = false;
    if (memStore && collapsed->mem_obj->memCache.io == MemObject::ioDone) {
        found = true;
        inSync = true;
        debugs(20, 7, "fully mem-loaded " << *collapsed);
    } else if (memStore && collapsed->hasMemStore()) {
        found = true;
        inSync = memStore->updateCollapsed(*collapsed);
        // TODO: handle entries attached to both memory and disk
    } else if (swapDir && collapsed->hasDisk()) {
        found = true;
        inSync = swapDir->updateCollapsed(*collapsed);
    } else {
        found = anchorCollapsed(*collapsed, inSync);
    }

    if (waitingToBeFreed && !found) {
        debugs(20, 3, "aborting detached " << *collapsed <<
                " because it was marked for deletion before we could attach it");
        collapsed->abort();
        return;
    }

    if (inSync) {
        debugs(20, 5, "synced " << *collapsed);
        collapsed->invokeHandlers();
        return;
    }

    if (found) { // unrecoverable problem syncing this entry
        debugs(20, 3, "aborting unsyncable " << *collapsed);
        collapsed->abort();
        return;
    }

    // the entry is still not in one of the caches
    debugs(20, 7, "waiting " << *collapsed);
}

/// Called for in-transit entries that are not yet anchored to a cache.
/// For cached entries, return true after synchronizing them with their cache
/// (making inSync true on success). For not-yet-cached entries, return false.
bool
Store::Controller::anchorCollapsed(StoreEntry &collapsed, bool &inSync)
{
    // this method is designed to work with collapsed transients only
    assert(collapsed.hasTransients());
    assert(collapsed.mem_obj->smpCollapsed);

    debugs(20, 7, "anchoring " << collapsed);

    bool found = false;
    if (memStore)
        found = memStore->anchorCollapsed(collapsed, inSync);
    if (!found && swapDir)
        found = swapDir->anchorCollapsed(collapsed, inSync);

    if (found) {
        if (inSync)
            debugs(20, 7, "anchored " << collapsed);
        else
            debugs(20, 5, "failed to anchor " << collapsed);
    } else {
        debugs(20, 7, "skipping not yet cached " << collapsed);
    }

    return found;
}

bool
Store::Controller::smpAware() const
{
    return memStore || (swapDir && swapDir->smpAware());
}

namespace Store {
static RefCount<Controller> TheRoot;
}

Store::Controller&
Store::Root()
{
    assert(TheRoot);
    return *TheRoot;
}

void
Store::Init(Controller *root)
{
    TheRoot = root ? root : new Controller;
}

void
Store::FreeMemory()
{
    TheRoot = nullptr;
}

