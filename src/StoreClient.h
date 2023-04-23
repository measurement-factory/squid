/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORECLIENT_H
#define SQUID_STORECLIENT_H

#include "acl/ChecklistFiller.h"
#include "base/AsyncCall.h"
#include "base/forward.h"
#include "dlink.h"
#include "StoreIOBuffer.h"
#include "StoreIOState.h"

/// A storeClientCopy() callback function.
///
/// Upon storeClientCopy() success, StoreIOBuffer::flags.error is zero, and
/// * HTTP response headers (if any) are available via MemObject::freshestReply();
/// * HTTP response body bytes (if any) are available via StoreIOBuffer.
///
/// STCB callbacks may use response semantics to detect certain EOF conditions.
/// Callbacks that expect HTTP headers may call store_client::atEof(). Similar
/// to clientStreamCallback() callbacks, callbacks dedicated to receiving HTTP
/// bodies may use zero StoreIOBuffer::length as an EOF condition.
///
/// Errors are indicated by setting StoreIOBuffer flags.error.
typedef void STCB(void *, StoreIOBuffer);

class StoreEntry;
class ACLFilledChecklist;
class LogTags;

/// a storeGetPublic*() caller
class StoreClient: public Acl::ChecklistFiller
{

public:
    ~StoreClient () override {}

    /// \return LogTags (if the class logs transactions) or nil (otherwise)
    virtual LogTags *loggingTags() const = 0;

protected:
    /// \returns whether the caller must collapse on the given entry
    /// Before returning true, updates common collapsing-related stats.
    /// See also: StoreEntry::hittingRequiresCollapsing().
    bool startCollapsingOn(const StoreEntry &, const bool doingRevalidation) const;

    // These methods only interpret Squid configuration. Their allowances are
    // provisional -- other factors may prevent collapsed forwarding. The first
    // two exist primarily to distinguish two major CF cases in callers code.
    /// whether Squid configuration allows us to become a CF initiator
    bool mayInitiateCollapsing() const { return onCollapsingPath(); }
    /// whether Squid configuration allows collapsing for this transaction
    bool onCollapsingPath() const;
};

#if USE_DELAY_POOLS
#include "DelayId.h"
#endif

namespace Store
{

/// XXX: TBD
using LegacyOffset = int64_t;

/// A space for storing HTTP body bytes returned by storeClientCopy().
///
/// During internal store_client operations, this buffer may also be temporary
/// used for serialized swap entry metadata and/or serialized HTTP headers.
class ReadBuffer
{
public:
    /// A StoreIOBuffer object for making the first storeClientCopy() request,
    /// providing our buffer space for storing any copied HTTP response body
    /// bytes. Current storeClientCopy() implementation does not support
    /// (positive) HTTP response body offsets for such first requests. Using
    /// this method instead of its spaceFor(0) equivalent clarifies that the
    /// caller may not be interested in body bytes at that zero offset.
    StoreIOBuffer initialSpace() { return spaceFor(0); }

    /// A StoreIOBuffer object for making a storeClientCopy() request for HTTP
    /// data at a given offset, providing our buffer space for storing any
    /// copied HTTP response body bytes. \sa initialSpace()
    StoreIOBuffer spaceFor(const LegacyOffset loffset) { return StoreIOBuffer(serialized_.size(), loffset, serialized_.data()); }

private:
    /// space for storing serialized Store entry bytes
    std::array<char, HTTP_REQBUF_SZ> serialized_;
};

} // namespace Store

/* keep track each client receiving data from that particular StoreEntry */

class store_client
{
    CBDATA_CLASS(store_client);

public:
    explicit store_client(StoreEntry *);
    ~store_client();

    /// An offset into the stored response bytes, including the HTTP response
    /// headers (if any). Note that this offset does not include Store entry
    /// metadata, because it is not a part of the stored response.
    /// \retval 0 means the client wants to read HTTP response headers.
    /// \retval +N the response byte that the client wants to read next.
    /// \retval -N should not occur.
    // TODO: Callers do not expect negative offset. Verify that the return
    // value cannot be negative and convert to unsigned in this case.
    int64_t readOffset() const { return copyInto.offset; }

    int getType() const;

    /// React to the end of reading the response from disk. There will be no
    /// more readHeader() and readBody() callbacks for the current storeRead()
    /// swapin after this notification.
    void noteSwapInDone(bool error);

    void doCopy (StoreEntry *e);
    void readHeader(const char *buf, ssize_t len);
    void readBody(const char *buf, ssize_t len);

    /// Request StoreIOBuffer-described response data via an asynchronous STCB
    /// callback. At most one outstanding request is allowed per store_client.
    void copy(StoreEntry *, StoreIOBuffer, STCB *, void *);

    void dumpStats(MemBuf * output, int clientNumber) const;

    // TODO: When STCB gets a dedicated Answer type, move this info there.
    /// Whether the last successful storeClientCopy() answer was known to
    /// contain the last body bytes of the HTTP response
    /// \retval true requesting bytes at higher offsets is futile
    /// \sa STCB
    bool atEof() const { return atEof_; }

#if STORE_CLIENT_LIST_DEBUG

    void *owner;
#endif

    StoreEntry *entry;      /* ptr to the parent StoreEntry, argh! */
    StoreIOState::Pointer swapin_sio;

    struct {
        /// whether we are expecting a response to be swapped in from disk
        /// (i.e. whether async storeRead() is currently in progress)
        // TODO: a better name reflecting the 'in' scope of the flag
        bool disk_io_pending;

        /// whether the store_client::doCopy()-initiated STCB sequence is
        /// currently in progress
        bool store_copying;
    } flags;

#if USE_DELAY_POOLS
    DelayId delayId;

    /// The maximum number of bytes the Store client can read/copy next without
    /// overflowing its buffer and without violating delay pool limits. Store
    /// I/O is not rate-limited, but we assume that the same number of bytes may
    /// be read from the Squid-to-server connection that may be rate-limited.
    int bytesWanted() const;

    void setDelayId(DelayId delay_id);
#endif

    dlink_node node;

private:
    bool moreToRead() const;
    bool canReadFromMemory() const;
    bool answeredOnce() const { return answers_ >= 1; }
    bool sendingHttpHeaders() const;
    int64_t nextHttpReadOffset() const;

    void fileRead();
    void scheduleDiskRead();
    void readFromMemory();
    void scheduleRead();
    bool startSwapin();
    void handleBodyFromDisk();
    void maybeWriteFromDiskToMemory(const StoreIOBuffer &);

    bool parseHttpHeadersFromDisk();
    bool tryParsingHttpHeaders();
    void skipHttpHeadersFromDisk();

    void fail();
    void callback(ssize_t);
    void noteCopiedBytes(size_t);
    void noteNews();
    void finishCallback();
    static void FinishCallback(store_client *);

    int type;
    bool object_ok;

    /// \copydoc atEof()
    bool atEof_;

    /// Storage and metadata associated with the current copy() request. Ought
    /// to be ignored when not answering a copy() request.
    StoreIOBuffer copyInto;

    /// the total number of finishCallback() calls
    unsigned int answers_;

    /// Accumulates raw bytes read from Store while answering the current copy()
    /// request. Buffer contents depends on the source and parsing stage; it may
    /// hold (parts of) swap metadata, HTTP response headers, and/or HTTP
    /// response body bytes.
    std::optional<Store::ParsingBuffer> parsingBuffer;

    StoreIOBuffer lastRead_; ///< buffer used for the last storeRead() call

    /* Until we finish stuffing code into store_client */

public:

    struct Callback {
        Callback ():callback_handler(nullptr), callback_data(nullptr) {}

        Callback (STCB *, void *);

        /// Whether the copy() answer is needed/expected (by the client) and has
        /// not been computed (by us). False during (asynchronous) answer
        /// delivery to the STCB callback_handler.
        bool pending() const;

        STCB *callback_handler;
        void *callback_data;
        CodeContextPointer codeContext; ///< Store client context

        /// a scheduled asynchronous finishCallback() call (or nil)
        AsyncCall::Pointer notifier;
    } _callback;
};

/// Asynchronously read HTTP response headers and/or body bytes from Store.
///
/// The requested zero-based HTTP body offset is specified via the
/// StoreIOBuffer::offset field. The first call (for a given store_client
/// object) must specify zero offset.
///
/// The requested HTTP body portion size is specified via the
/// StoreIOBuffer::length field. The function may return fewer body bytes.
///
/// See STCB for result delivery details.
void storeClientCopy(store_client *, StoreEntry *, StoreIOBuffer, STCB *, void *);

store_client* storeClientListAdd(StoreEntry * e, void *data);
int storeUnregister(store_client * sc, StoreEntry * e, void *data);
int storePendingNClients(const StoreEntry * e);
int storeClientIsThisAClient(store_client * sc, void *someClient);

#endif /* SQUID_STORECLIENT_H */

