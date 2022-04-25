/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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

typedef void STCB(void *, StoreIOBuffer);   /* store callback */

class StoreEntry;
class ACLFilledChecklist;
class LogTags;

/// a storeGetPublic*() caller
class StoreClient: public Acl::ChecklistFiller
{

public:
    virtual ~StoreClient () {}

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

/* keep track each client receiving data from that particular StoreEntry */

class store_client
{
    CBDATA_CLASS(store_client);

public:
    store_client(StoreEntry *);
    ~store_client();

    /// Whether this Store client requires memory-stored response content. A
    /// false result does not mean the client never reads from memory, only that
    /// it has other means of getting the response content (e.g. from disk) and,
    /// hence, will keep working even if unread content is purged from memory.
    bool reliesOnReadingFromMemory() const;

    /// The offset of the stored response that the client wants to read next.
    /// A zero offset means the client wants to read HTTP response headers.
    int64_t readOffset() const { return copyInto.offset; }

    int getType() const;

    /// React to the end of reading the response from disk. There will be no
    /// (more) readHeader() and readBody() callbacks for the current storeRead()
    /// swapin after this notification.
    void noteSwapInDone(bool error);

    void doCopy (StoreEntry *e);
    void readHeader(const char *buf, ssize_t len);
    void readBody(const char *buf, ssize_t len);

    /// Request StoreIOBuffer-described response data via an asynchronous STCB
    /// callback. At most one outstanding request is allowed per store_client.
    void copy(StoreEntry *, StoreIOBuffer, STCB *, void *);

    void dumpStats(MemBuf * output, int clientNumber) const;

    int64_t cmp_offset;
#if STORE_CLIENT_LIST_DEBUG

    void *owner;
#endif

    StoreEntry *entry;      /* ptr to the parent StoreEntry, argh! */
    StoreIOState::Pointer swapin_sio;

    struct {
        /// whether we are expecting a response to be swapped in from disk
        /// (i.e. whether storeRead() is currently in progress)
        bool disk_io_pending;

        /// whether store_client::doCopy() is currently in progress
        bool store_copying;
    } flags;

#if USE_DELAY_POOLS
    DelayId delayId;

    /// the number of bytes we can read without violating delay pool limits
    int bytesWanted() const;

    void setDelayId(DelayId delay_id);
#endif

    dlink_node node;

private:
    bool moreToSend() const;

    void fileRead();
    void scheduleDiskRead();
    void scheduleMemRead();
    void scheduleRead();
    bool startSwapin();
    bool unpackHeader(char const *buf, ssize_t len);

    void fail();
    void callback(ssize_t);
    void noteCopiedBytes(size_t);
    void noteEof();
    void noteNews();
    void finishCallback();
    static void FinishCallback(store_client *);

    int type;
    bool object_ok;

    /// Storage and metadata associated with the current copy() request. Ought
    /// to be ignored when not answering a copy() request.
    StoreIOBuffer copyInto;

    /// The number of bytes loaded from Store into copyInto while answering the
    /// current copy() request. Ought to be ignored when not answering.
    size_t copiedSize;

    /* Until we finish stuffing code into store_client */

public:

    struct Callback {
        Callback ():callback_handler(NULL), callback_data(NULL) {}

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

void storeClientCopy(store_client *, StoreEntry *, StoreIOBuffer, STCB *, void *);
store_client* storeClientListAdd(StoreEntry * e, void *data);
int storeClientCopyPending(store_client *, StoreEntry * e, void *data);
int storeUnregister(store_client * sc, StoreEntry * e, void *data);
int storePendingNClients(const StoreEntry * e);
int storeClientIsThisAClient(store_client * sc, void *someClient);

#endif /* SQUID_STORECLIENT_H */

