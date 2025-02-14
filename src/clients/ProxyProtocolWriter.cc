/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "clients/ProxyProtocolWriter.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "FwdState.h"
#include "HttpRequest.h"
#include "pconn.h"
#include "StatCounters.h"

CBDATA_CLASS_INIT(ProxyProtocolWriter);

ProxyProtocolWriterAnswer::~ProxyProtocolWriterAnswer()
{
    delete squidError.get();
}

std::ostream &
operator <<(std::ostream &os, const ProxyProtocolWriterAnswer &answer)
{
    return os << answer.conn << ", " << answer.squidError;
}

ProxyProtocolWriter::ProxyProtocolWriter(const SBuf &hdr, const Comm::ConnectionPointer &conn, const HttpRequest::Pointer &req, const AsyncCallback<Answer> &aCallback, const AccessLogEntryPointer &alp):
    AsyncJob("ProxyProtocolWriter"),
    header(hdr),
    connection(conn),
    request(req),
    callback(aCallback),
    al(alp),
    headerWritten(false)
{
    debugs(17, 5, "ProxyProtocolWriter constructed, this=" << (void*)this);
    assert(request);
    assert(connection);
    watchForClosures();
}

ProxyProtocolWriter::~ProxyProtocolWriter()
{
    debugs(17, 5, "ProxyProtocolWriter destructed, this=" << (void*)this);
}

bool
ProxyProtocolWriter::doneAll() const
{
    return !callback || headerWritten;
}

void ProxyProtocolWriter::start()
{
    AsyncJob::start();

    // we own this Comm::Connection object and its fd exclusively, but must bail
    // if others started closing the socket while we were waiting to start()
    assert(Comm::IsConnOpen(connection));

    if (fd_table[connection->fd].closing()) {
        bailWith(new ErrorState(ERR_CANNOT_FORWARD, Http::scServiceUnavailable, request.getRaw(), al));
        return;
    }

    writeHeader();
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
    // TODO: add a specific err_type
    bailWith(new ErrorState(ERR_CANNOT_FORWARD, Http::scBadGateway, request.getRaw(), al));
}

/// make sure we quit if/when the connection is gone
void
ProxyProtocolWriter::watchForClosures()
{
    Must(Comm::IsConnOpen(connection));
    Must(!fd_table[connection->fd].closing());

    debugs(17, 5, connection);

    Must(!closer);
    typedef CommCbMemFunT<ProxyProtocolWriter, CommCloseCbParams> Dialer;
    closer = JobCallback(9, 5, Dialer, this, ProxyProtocolWriter::handleConnectionClosure);
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

    writer = JobCallback(5, 5, Dialer, this, ProxyProtocolWriter::handleWrittenHeader);
    Comm::Write(connection, &mb, writer);
}

void
ProxyProtocolWriter::handleWrittenHeader(const CommIoCbParams &io)
{
    Must(writer);
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
    Must(error);
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
    assert(callback.answer().positive());
    assert(Comm::IsConnOpen(connection));
    callback.answer().conn = connection;
    disconnect();
    callBack();
}

void
ProxyProtocolWriter::countFailingConnection()
{
    assert(connection);
    if (noteFwdPconnUse && connection->isOpen())
        fwdPconnPool->noteUses(fd_table[connection->fd].pconn.uses);
}

void
ProxyProtocolWriter::disconnect()
{
    const auto stillOpen = Comm::IsConnOpen(connection);

    if (closer) {
        if (stillOpen)
            comm_remove_close_handler(connection->fd, closer);
        closer = nullptr;
    }

    connection = nullptr; // may still be open
}

void
ProxyProtocolWriter::callBack()
{
    debugs(17, 5, callback.answer().conn << status());
    assert(!connection); // returned inside callback.answer() or gone
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
        assert(!callback);
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

    if (stopReason != nullptr) {
        buf.append(" stopped, reason:", 16);
        buf.appendf("%s",stopReason);
    }
    if (connection != nullptr)
        buf.appendf(" FD %d", connection->fd);
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}

