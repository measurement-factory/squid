/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTS_PROXYPROTOCOLWRITER_H
#define SQUID_SRC_CLIENTS_PROXYPROTOCOLWRITER_H

#include "base/AsyncCallbacks.h"
#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "clients/forward.h"
#include "CommCalls.h"
#include "comm/Connection.h"
#include "http/StatusCode.h"
#include "sbuf/SBuf.h"

class AccessLogEntry;
class ErrorState;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

/// Proxy protocol header sending results (supplied via a callback).
class ProxyProtocolWriterAnswer
{
public:
    ProxyProtocolWriterAnswer() {}
    ~ProxyProtocolWriterAnswer(); ///< deletes squidError if it is still set

    bool positive() const { return !squidError; }

    /// answer recipients must clear the error member in order to keep its info
    /// XXX: We should refcount ErrorState instead of cbdata-protecting it.
    CbcPointer<ErrorState> squidError; ///< problem details (or nil)

    Comm::ConnectionPointer conn;
};

std::ostream &operator <<(std::ostream &, const ProxyProtocolWriterAnswer &);

/// Sends PROXY protocol header to a proxy using the given open
/// TCP connectection to that proxy. Owns the connection until
/// the header is sent.
class ProxyProtocolWriter: virtual public AsyncJob
{

    CBDATA_CHILD(ProxyProtocolWriter);

public:
    using Answer = ProxyProtocolWriterAnswer;

    ProxyProtocolWriter(const SBuf &hdr, const Comm::ConnectionPointer &, const HttpRequestPointer &, const AsyncCallback<Answer> &, const AccessLogEntryPointer &);
    ProxyProtocolWriter(const ProxyProtocolWriter &) = delete;
    ProxyProtocolWriter &operator =(const ProxyProtocolWriter &) = delete;

    /// hack: whether the connection requires fwdPconnPool->noteUses()
    bool noteFwdPconnUse;

protected:
    /* AsyncJob API */
    ~ProxyProtocolWriter() override;
    void start() override;
    bool doneAll() const override;
    void swanSong() override;
    const char *status() const override;

    void writeHeader();
    void handleWrittenHeader(const CommIoCbParams &);
    void handleConnectionClosure(const CommCloseCbParams&);
    void watchForClosures();

private:
    /// sends the given error to the initiator
    void bailWith(ErrorState*);

    /// sends the ready-to-use tunnel to the initiator
    void sendSuccess();

    /// a bailWith(), sendSuccess() helper: sends results to the initiator
    void callBack();

    /// stops monitoring the connection
    void disconnect();

    /// updates connection usage history before the connection is closed
    void countFailingConnection();

    AsyncCall::Pointer writer; ///< called when the request has been written
    AsyncCall::Pointer closer; ///< called when the connection is being closed

    SBuf header; // v2 PROXY protocol header
    Comm::ConnectionPointer connection; ///< TCP connection to the cache_peer
    HttpRequestPointer request; ///< peer connection trigger or cause
    AsyncCallback<Answer> callback; ///< answer destination
    AccessLogEntryPointer al; ///< info for the future access.log entry
    bool headerWritten; ///< whether we successfully wrote the request
};

#endif /* SQUID_SRC_CLIENTS_PROXYPROTOCOLWRITER_H  */ 

