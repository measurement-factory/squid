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
#include "comm/Connection.h"
#include "CommCalls.h"
#include "http/forward.h"
#include "http/StatusCode.h"
#include "sbuf/SBuf.h"

class ErrorState;
class AccessLogEntry;
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

/// Sends PROXY protocol header to a cache_peer or server. using the given open
/// TCP connection. Owns the connection until the header is sent.
class ProxyProtocolWriter: virtual public AsyncJob
{
    CBDATA_CHILD(ProxyProtocolWriter);

public:
    using Answer = ProxyProtocolWriterAnswer;

    ProxyProtocolWriter(const SBuf &hdr, const Comm::ConnectionPointer &, const HttpRequestPointer &, const AsyncCallback<Answer> &, const AccessLogEntryPointer &);
    ProxyProtocolWriter(const ProxyProtocolWriter &) = delete;
    ProxyProtocolWriter &operator =(const ProxyProtocolWriter &) = delete;

protected:
    /* AsyncJob API */
    ~ProxyProtocolWriter() override;
    void start() override;
    bool doneAll() const override;
    void swanSong() override;
    const char *status() const override;

    void handleConnectionClosure(const CommCloseCbParams&);
    void watchForClosures();
    void writeHeader();
    void handleWrittenHeader(const CommIoCbParams &);

private:
    void bailWith(ErrorState*);
    void sendSuccess();
    void callBack();
    void disconnect();
    void countFailingConnection();

    const SBuf header; ///< PROXY protocol header we must write
    Comm::ConnectionPointer connection; ///< TCP connection to a cache_peer or server
    const HttpRequestPointer request; ///< the connection trigger or cause
    AsyncCallback<Answer> callback; ///< answer destination
    AccessLogEntryPointer al; ///< info for the future access.log entry

    AsyncCall::Pointer writer; ///< called when the request has been written
    AsyncCall::Pointer closer; ///< called when the connection is being closed

    bool headerWritten = false; ///< whether we successfully wrote the request
};

/// generates a serialized PROXY protocol header for the given transaction (if
/// such a header is required) or returns nil (otherwise)
std::optional<SBuf> OutgoingProxyProtocolHeader(const HttpRequestPointer &, const AccessLogEntryPointer &);

#endif /* SQUID_SRC_CLIENTS_PROXYPROTOCOLWRITER_H */

