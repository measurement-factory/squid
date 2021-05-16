/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Comm */

#ifndef COMMREAD_H
#define COMMREAD_H

#include "base/CbDataList.h"
#include "comm.h"
#include "comm/forward.h"
#include "CommCalls.h"

class CommRead
{

public:
    CommRead();
    CommRead(const Comm::ConnectionPointer &c, char *buf, int len, AsyncCall::Pointer &callback);
    Comm::ConnectionPointer conn;
    char *buf;
    int len;
    AsyncCall::Pointer callback;
};

inline
std::ostream &
operator <<(std::ostream &os, const CommRead &aRead)
{
    return os << aRead.conn << ", len=" << aRead.len << ", buf=" << aRead.buf;
}

class DeferredRead
{

public:
    DeferredRead() {}
    DeferredRead(const AsyncCall::Pointer &aReader, const Comm::ConnectionPointer &c) : reader(aReader), conn(c) {}
    void cancel(const char *reason);
    explicit operator bool() const { return bool(reader); }
    void addCloseHandler(AsyncCall::Pointer &);
    void removeCloseHandler();

    AsyncCall::Pointer reader; ///< pending reader callback
    AsyncCall::Pointer closer; ///< internal close handler used by Comm
    Comm::ConnectionPointer conn;

private:
};

class DeferredReadManager
{

public:
    ~DeferredReadManager();
    void delayRead(DeferredRead const &);
    void kickReads(int const count);

private:
    static CLCB CloseHandler;
    static DeferredRead popHead(CbDataListContainer<DeferredRead> &deferredReads);
    void kickARead(DeferredRead &);
    void flushReads();
    CbDataListContainer<DeferredRead> deferredReads;
};

#endif /* COMMREAD_H */

