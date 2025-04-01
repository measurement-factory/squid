/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/Assure.h"
#include "CachePeer.h"
#include "clients/ProxyProtocolWriter.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "FwdState.h"
#include "HttpRequest.h"
#include "pconn.h"
#include "proxyp/Header.h"
#include "proxyp/OutgoingConfig.h"
#include "SquidConfig.h"
#include "StatCounters.h"

/* ProxyProtocolWriter */

CBDATA_CLASS_INIT(ProxyProtocolWriter);

ProxyProtocolWriter::ProxyProtocolWriter(const SBuf &hdr, const Comm::ConnectionPointer &conn, const HttpRequest::Pointer &req, const AsyncCallback<Answer> &aCallback, const AccessLogEntryPointer &alp):
    AsyncJob("ProxyProtocolWriter"),
    header(hdr),
    connection(conn),
    request(req),
    callback(aCallback),
    al(alp)
{
    debugs(17, 5, "constructing, this=" << static_cast<void*>(this));
    Assure(request);
    Assure(connection);
    Assure(!header.isEmpty());
    watchForClosures();
}

ProxyProtocolWriter::~ProxyProtocolWriter()
{
    debugs(17, 5, "destructing, this=" << static_cast<void*>(this));
}

bool
ProxyProtocolWriter::doneAll() const
{
    return !callback || headerWritten;
}

void
ProxyProtocolWriter::start()
{
    AsyncJob::start();

    // we own this Comm::Connection object and its fd exclusively, but must bail
    // if others started closing the socket while we were waiting to start()
    Assure(Comm::IsConnOpen(connection));
    if (fd_table[connection->fd].closing()) {
        bailWith(new ErrorState(ERR_CANNOT_FORWARD, Http::scServiceUnavailable, request.getRaw(), al));
        return;
    }

    writeHeader();
    // We do not read because PROXY protocol has no responses. If peer sends
    // something while we are writing, subsequent protocol handler will read it
    // (after we are done writing).
}

void
ProxyProtocolWriter::handleConnectionClosure(const CommCloseCbParams &)
{
    closer = nullptr;
    if (connection) {
        countFailingConnection();
        connection->noteClosure();
        connection = nullptr;
    }
    bailWith(new ErrorState(ERR_CANNOT_FORWARD, Http::scServiceUnavailable, request.getRaw(), al));
}

/// make sure we quit if/when the connection is gone
void
ProxyProtocolWriter::watchForClosures()
{
    Assure(Comm::IsConnOpen(connection));
    Assure(!fd_table[connection->fd].closing());

    debugs(17, 5, connection);

    Assure(!closer);
    using Dialer = CommCbMemFunT<ProxyProtocolWriter, CommCloseCbParams>;
    closer = JobCallback(17, 5, Dialer, this, ProxyProtocolWriter::handleConnectionClosure);
    comm_add_close_handler(connection->fd, closer);
}

void
ProxyProtocolWriter::writeHeader()
{
    debugs(17, 5, connection);

    // XXX: Avoid this copying by adding an SBuf-friendly Comm::Write()!
    MemBuf mb;
    mb.init();
    mb.append(header.rawContent(), header.length());

    using Dialer =  CommCbMemFunT<ProxyProtocolWriter, CommIoCbParams>;
    writer = JobCallback(17, 5, Dialer, this, ProxyProtocolWriter::handleWrittenHeader);
    Comm::Write(connection, &mb, writer);
}

void
ProxyProtocolWriter::handleWrittenHeader(const CommIoCbParams &io)
{
    Assure(writer);
    writer = nullptr;

    if (io.flag == Comm::ERR_CLOSING)
        return;

    request->hier.notePeerWrite();

    if (io.flag != Comm::OK) {
        const auto error = new ErrorState(ERR_WRITE_ERROR, Http::scBadGateway, request.getRaw(), al);
        error->xerrno = io.xerrno;
        bailWith(error);
        return;
    }

    statCounter.server.all.kbytes_out += io.size;
    statCounter.server.other.kbytes_out += io.size;
    headerWritten = true;
    debugs(17, 5, status());
}

void
ProxyProtocolWriter::bailWith(ErrorState *error)
{
    Assure(error);
    callback.answer().squidError = error;

    if (const auto failingConnection = connection) {
        countFailingConnection();
        disconnect();
        failingConnection->close();
    }

    callBack();
}

void
ProxyProtocolWriter::sendSuccess()
{
    Assure(callback.answer().positive());
    Assure(Comm::IsConnOpen(connection));
    callback.answer().conn = connection;
    disconnect();
    callBack();
}

void
ProxyProtocolWriter::countFailingConnection()
{
    Assure(connection);
    NoteOutgoingConnectionFailure(connection->getPeer(), Http::scNone);
}

void
ProxyProtocolWriter::disconnect()
{
    if (closer) {
        if (Comm::IsConnOpen(connection))
            comm_remove_close_handler(connection->fd, closer);
        closer = nullptr;
    }

    connection = nullptr; // may still be open
}

void
ProxyProtocolWriter::callBack()
{
    debugs(17, 5, callback.answer() << status());
    Assure(!connection); // returned inside callback.answer() or gone
    ScheduleCallHere(callback.release());
}

void
ProxyProtocolWriter::swanSong()
{
    AsyncJob::swanSong();

    if (callback) {
        if (headerWritten && Comm::IsConnOpen(connection)) {
            sendSuccess();
        } else {
            // job-ending emergencies like handleStopRequest() or callException()
            bailWith(new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al));
        }
        Assure(!callback);
    }
}

const char *
ProxyProtocolWriter::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [state:", 8);
    if (headerWritten) buf.append("w", 1); // header sent
    if (!callback) buf.append("x", 1); // caller informed
    if (stopReason)
        buf.appendf(" stopped, reason: %s", stopReason);
    if (connection)
        buf.appendf(" %s%" PRIu64, connection->id.prefix(), connection->id.value);
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}

/* ProxyProtocolWriterAnswer */

ProxyProtocolWriterAnswer::~ProxyProtocolWriterAnswer()
{
    delete squidError.get();
}

std::ostream &
operator <<(std::ostream &os, const ProxyProtocolWriterAnswer &answer)
{
    if (const auto squidError = answer.squidError.get())
        os << squidError;
    // no separator because the two reported items should be mutually exclusive
    if (const auto conn = answer.conn.getRaw())
        os << conn->id;
    return os;
}

std::optional<SBuf>
OutgoingProxyProtocolHeader(const HttpRequestPointer &request, const AccessLogEntryPointer &al)
{
    if (!Config.proxyProtocolOutgoing)
        return std::nullopt;

    if (const auto &aclList = Config.proxyProtocolOutgoing->aclList) {
        ACLFilledChecklist ch(aclList, request.getRaw());
        ch.al = al;
        ch.syncAle(request.getRaw(), nullptr);
        if (!ch.fastCheck().allowed())
            return std::nullopt;
    }

    static const SBuf v2("2.0");
    const auto local = request && request->masterXaction->initiator.internalClient();
    ProxyProtocol::Header header(v2, local ? ProxyProtocol::Two::cmdLocal : ProxyProtocol::Two::cmdProxy);
    Config.proxyProtocolOutgoing->fill(header, al);
    return header.pack();
}

