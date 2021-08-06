/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/Xaction.h"
#include "base/JobWait.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "err_detail_type.h"
#include "fde.h"
#include "FwdState.h"
#include "globals.h"
#include "HttpReply.h"
#include "icap_log.h"
#include "ipcache.h"
#include "pconn.h"
#include "security/PeerConnector.h"
#include "SquidConfig.h"
#include "SquidTime.h"

/// Gives Security::PeerConnector access to Answer in the PeerPoolMgr callback dialer.
class MyIcapAnswerDialer: public UnaryMemFunT<Adaptation::Icap::Xaction, Security::EncryptorAnswer, Security::EncryptorAnswer&>,
    public Security::PeerConnector::CbDialer
{
public:
    MyIcapAnswerDialer(const JobPointer &aJob, Method aMethod):
        UnaryMemFunT<Adaptation::Icap::Xaction, Security::EncryptorAnswer, Security::EncryptorAnswer&>(aJob, aMethod, Security::EncryptorAnswer()) {}

    /* Security::PeerConnector::CbDialer API */
    virtual Security::EncryptorAnswer &answer() { return arg1; }
};

namespace Ssl
{
/// A simple PeerConnector for Secure ICAP services. No SslBump capabilities.
class IcapPeerConnector: public Security::PeerConnector {
    CBDATA_CLASS(IcapPeerConnector);
public:
    IcapPeerConnector(
        Adaptation::Icap::ServiceRep::Pointer &service,
        const Comm::ConnectionPointer &aServerConn,
        AsyncCall::Pointer &aCallback,
        AccessLogEntry::Pointer const &alp,
        const time_t timeout = 0):
        AsyncJob("Ssl::IcapPeerConnector"),
        Security::PeerConnector(aServerConn, aCallback, alp, timeout), icapService(service) {}

    /* Security::PeerConnector API */
    virtual bool initialize(Security::SessionPointer &);
    virtual void noteNegotiationDone(ErrorState *error);
    virtual Security::ContextPointer getTlsContext() {
        return icapService->sslContext;
    }

private:
    Adaptation::Icap::ServiceRep::Pointer icapService;
};
} // namespace Ssl

CBDATA_NAMESPACED_CLASS_INIT(Ssl, IcapPeerConnector);

Adaptation::Icap::Xaction::Xaction(const char *aTypeName, Adaptation::Icap::ServiceRep::Pointer &aService):
    AsyncJob(aTypeName),
    Adaptation::Initiate(aTypeName),
    icapRequest(NULL),
    icapReply(NULL),
    attempts(0),
    theService(aService),
    commEof(false),
    reuseConnection(true),
    isRetriable(true),
    isRepeatable(true),
    ignoreLastWrite(false),
    alep(new AccessLogEntry),
    al(*alep)
{
    debugs(93,3, typeName << " constructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
    const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initAdaptation);
    icapRequest = new HttpRequest(mx);
    HTTPMSGLOCK(icapRequest);
    icap_tr_start = current_time;
    memset(&icap_tio_start, 0, sizeof(icap_tio_start));
    memset(&icap_tio_finish, 0, sizeof(icap_tio_finish));
}

Adaptation::Icap::Xaction::~Xaction()
{
    debugs(93,3, typeName << " destructed, this=" << this <<
           " [icapx" << id << ']'); // we should not call virtual status() here
    HTTPMSGUNLOCK(icapRequest);
}

AccessLogEntry::Pointer
Adaptation::Icap::Xaction::masterLogEntry()
{
    AccessLogEntry::Pointer nil;
    return nil;
}

Adaptation::Icap::ServiceRep &
Adaptation::Icap::Xaction::service()
{
    Must(theService != NULL);
    return *theService;
}

void Adaptation::Icap::Xaction::disableRetries()
{
    debugs(93,5, typeName << (isRetriable ? " from now on" : " still") <<
           " cannot be retried " << status());
    isRetriable = false;
}

void Adaptation::Icap::Xaction::disableRepeats(const char *reason)
{
    debugs(93,5, typeName << (isRepeatable ? " from now on" : " still") <<
           " cannot be repeated because " << reason << status());
    isRepeatable = false;
}

void Adaptation::Icap::Xaction::start()
{
    Adaptation::Initiate::start();
}

static void
icapLookupDnsResults(const ipcache_addrs *ia, const Dns::LookupDetails &, void *data)
{
    Adaptation::Icap::Xaction *xa = static_cast<Adaptation::Icap::Xaction *>(data);
    /// TODO: refactor with CallJobHere1, passing either std::optional (after upgrading to C++17)
    /// or Optional<Ip::Address> (when it can take non-trivial types)
    xa->dnsLookupDone(ia);
}

// TODO: obey service-specific, OPTIONS-reported connection limit
void
Adaptation::Icap::Xaction::openConnection()
{
    Must(!haveConnection());

    Adaptation::Icap::ServiceRep &s = service();

    if (!TheConfig.reuse_connections)
        disableRetries(); // this will also safely drain pconn pool

    if (const auto pconn = s.getIdleConnection(isRetriable)) {
        useTransportConnection(pconn);
        return;
    }

    disableRetries(); // we only retry pconn failures

    // Attempt to open a new connection...
    debugs(93,3, typeName << " opens connection to " << s.cfg().host.termedBuf() << ":" << s.cfg().port);

    // Locate the Service IP(s) to open
    ipcache_nbgethostbyname(s.cfg().host.termedBuf(), icapLookupDnsResults, this);
}

void
Adaptation::Icap::Xaction::dnsLookupDone(const ipcache_addrs *ia)
{
    Adaptation::Icap::ServiceRep &s = service();

    if (ia == NULL) {
        debugs(44, DBG_IMPORTANT, "ICAP: Unknown service host: " << s.cfg().host);

#if WHEN_IPCACHE_NBGETHOSTBYNAME_USES_ASYNC_CALLS
        dieOnConnectionFailure(); // throws
#else // take a step back into protected Async call dialing.
        CallJobHere(93, 3, this, Xaction, Xaction::dieOnConnectionFailure);
#endif
        return;
    }

    const Comm::ConnectionPointer conn = new Comm::Connection();
    conn->remote = ia->current();
    conn->remote.port(s.cfg().port);
    getOutgoingAddress(nullptr, conn);

    // TODO: service bypass status may differ from that of a transaction
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommConnectCbParams> ConnectDialer;
    AsyncCall::Pointer callback = JobCallback(93, 3, ConnectDialer, this, Adaptation::Icap::Xaction::noteCommConnected);
    const auto cs = new Comm::ConnOpener(conn, callback, TheConfig.connect_timeout(service().cfg().bypass));
    cs->setHost(s.cfg().host.termedBuf());
    transportWait.start(cs, callback);
}

/*
 * This event handler is necessary to work around the no-rentry policy
 * of Adaptation::Icap::Xaction::callStart()
 */
#if 0
void
Adaptation::Icap::Xaction::reusedConnection(void *data)
{
    debugs(93, 5, HERE << "reused connection");
    Adaptation::Icap::Xaction *x = (Adaptation::Icap::Xaction*)data;
    x->noteCommConnected(Comm::OK);
}
#endif

void Adaptation::Icap::Xaction::closeConnection()
{
    if (haveConnection()) {

        if (closer != NULL) {
            comm_remove_close_handler(connection->fd, closer);
            closer = NULL;
        }

        commUnsetConnTimeout(connection);

        cancelRead(); // may not work

        if (reuseConnection && !doneWithIo()) {
            //status() adds leading spaces.
            debugs(93,5, HERE << "not reusing pconn due to pending I/O" << status());
            reuseConnection = false;
        }

        if (reuseConnection)
            disableRetries();

        const bool reset = !reuseConnection &&
                           (al.icap.outcome == xoGone || al.icap.outcome == xoError);

        Adaptation::Icap::ServiceRep &s = service();
        s.putConnection(connection, reuseConnection, reset, status());

        writer = NULL;
        reader = NULL;
        connection = NULL;
    }
}

/// called when the connection attempt to an ICAP service completes (successfully or not)
void Adaptation::Icap::Xaction::noteCommConnected(const CommConnectCbParams &io)
{
    transportWait.finish();

    if (io.flag != Comm::OK) {
        dieOnConnectionFailure(); // throws
        return;
    }

    useTransportConnection(io.conn);
}

/// React to the availability of a transport connection to the ICAP service.
/// The given connection may (or may not) be secured already.
void
Adaptation::Icap::Xaction::useTransportConnection(const Comm::ConnectionPointer &conn)
{
    assert(Comm::IsConnOpen(conn));
    assert(!connection);

    // If it is a reused connection and the TLS object is built
    // we should not negotiate new TLS session
    const auto &ssl = fd_table[conn->fd].ssl;
    if (!ssl && service().cfg().secure.encryptTransport) {
        // XXX: Exceptions orphan conn.
        CbcPointer<Adaptation::Icap::Xaction> me(this);
        AsyncCall::Pointer callback = asyncCall(93, 4, "Adaptation::Icap::Xaction::handleSecuredPeer",
                                                MyIcapAnswerDialer(me, &Adaptation::Icap::Xaction::handleSecuredPeer));

        const auto sslConnector = new Ssl::IcapPeerConnector(theService, conn, callback, masterLogEntry(), TheConfig.connect_timeout(service().cfg().bypass));

        encryptionWait.start(sslConnector, callback);
        return;
    }

    useIcapConnection(conn);
}

/// react to the availability of a fully-ready ICAP connection
void
Adaptation::Icap::Xaction::useIcapConnection(const Comm::ConnectionPointer &conn)
{
    assert(!connection);
    assert(conn);
    assert(Comm::IsConnOpen(conn));
    connection = conn;
    service().noteConnectionUse(connection);

    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  asyncCall(93, 5, "Adaptation::Icap::Xaction::noteCommTimedout",
                                      TimeoutDialer(this,&Adaptation::Icap::Xaction::noteCommTimedout));
    commSetConnTimeout(connection, TheConfig.connect_timeout(service().cfg().bypass), timeoutCall);

    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommCloseCbParams> CloseDialer;
    closer =  asyncCall(93, 5, "Adaptation::Icap::Xaction::noteCommClosed",
                        CloseDialer(this,&Adaptation::Icap::Xaction::noteCommClosed));
    comm_add_close_handler(connection->fd, closer);

    startShoveling();
}

void Adaptation::Icap::Xaction::dieOnConnectionFailure()
{
    debugs(93, 2, HERE << typeName <<
           " failed to connect to " << service().cfg().uri);
    service().noteConnectionFailed("failure");
    detailError(ERR_DETAIL_ICAP_XACT_START);
    throw TexcHere("cannot connect to the ICAP service");
}

void Adaptation::Icap::Xaction::scheduleWrite(MemBuf &buf)
{
    Must(haveConnection());

    // comm module will free the buffer
    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommIoCbParams> Dialer;
    writer = JobCallback(93, 3,
                         Dialer, this, Adaptation::Icap::Xaction::noteCommWrote);

    Comm::Write(connection, &buf, writer);
    updateTimeout();
}

void Adaptation::Icap::Xaction::noteCommWrote(const CommIoCbParams &io)
{
    Must(writer != NULL);
    writer = NULL;

    if (ignoreLastWrite) {
        // a hack due to comm inability to cancel a pending write
        ignoreLastWrite = false;
        debugs(93, 7, HERE << "ignoring last write; status: " << io.flag);
    } else {
        Must(io.flag == Comm::OK);
        al.icap.bytesSent += io.size;
        updateTimeout();
        handleCommWrote(io.size);
    }
}

// communication timeout with the ICAP service
void Adaptation::Icap::Xaction::noteCommTimedout(const CommTimeoutCbParams &)
{
    debugs(93, 2, HERE << typeName << " failed: timeout with " <<
           theService->cfg().methodStr() << " " <<
           theService->cfg().uri << status());
    reuseConnection = false;
    assert(haveConnection());
    theService->noteConnectionFailed("timedout");
    closeConnection();
    throw TextException("timed out while talking to the ICAP service", Here());
}

// unexpected connection close while talking to the ICAP service
void Adaptation::Icap::Xaction::noteCommClosed(const CommCloseCbParams &)
{
    closer = NULL;
    detailError(ERR_DETAIL_ICAP_XACT_CLOSE);
    mustStop("ICAP service connection externally closed");
}

void Adaptation::Icap::Xaction::callException(const std::exception  &e)
{
    setOutcome(xoError);
    service().noteFailure();
    Adaptation::Initiate::callException(e);
}

void Adaptation::Icap::Xaction::callEnd()
{
    if (doneWithIo()) {
        debugs(93, 5, HERE << typeName << " done with I/O" << status());
        closeConnection();
    }
    Adaptation::Initiate::callEnd(); // may destroy us
}

bool Adaptation::Icap::Xaction::doneAll() const
{
    return !transportWait && !encryptionWait && !reader && !writer && Adaptation::Initiate::doneAll();
}

void Adaptation::Icap::Xaction::updateTimeout()
{
    Must(haveConnection());

    if (reader != NULL || writer != NULL) {
        // restart the timeout before each I/O
        // XXX: why does Config.Timeout lacks a write timeout?
        // TODO: service bypass status may differ from that of a transaction
        typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommTimeoutCbParams> TimeoutDialer;
        AsyncCall::Pointer call = JobCallback(93, 5, TimeoutDialer, this, Adaptation::Icap::Xaction::noteCommTimedout);
        commSetConnTimeout(connection, TheConfig.io_timeout(service().cfg().bypass), call);
    } else {
        // clear timeout when there is no I/O
        // Do we need a lifetime timeout?
        commUnsetConnTimeout(connection);
    }
}

void Adaptation::Icap::Xaction::scheduleRead()
{
    Must(haveConnection());
    Must(!reader);
    Must(readBuf.length() < SQUID_TCP_SO_RCVBUF); // will expand later if needed

    typedef CommCbMemFunT<Adaptation::Icap::Xaction, CommIoCbParams> Dialer;
    reader = JobCallback(93, 3, Dialer, this, Adaptation::Icap::Xaction::noteCommRead);
    Comm::Read(connection, reader);
    updateTimeout();
}

// comm module read a portion of the ICAP response for us
void Adaptation::Icap::Xaction::noteCommRead(const CommIoCbParams &io)
{
    Must(reader != NULL);
    reader = NULL;

    Must(io.flag == Comm::OK);

    // TODO: tune this better to expected message sizes
    readBuf.reserveCapacity(SQUID_TCP_SO_RCVBUF);
    // we are not asked to grow beyond the allowed maximum
    Must(readBuf.length() < SQUID_TCP_SO_RCVBUF);
    // now we can ensure that there is space to read new data,
    // even if readBuf.spaceSize() currently returns zero.
    readBuf.rawAppendStart(1);

    CommIoCbParams rd(this); // will be expanded with ReadNow results
    rd.conn = io.conn;

    switch (Comm::ReadNow(rd, readBuf)) {
    case Comm::INPROGRESS:
        if (readBuf.isEmpty())
            debugs(33, 2, io.conn << ": no data to process, " << xstrerr(rd.xerrno));
        scheduleRead();
        return;

    case Comm::OK:
        al.icap.bytesRead += rd.size;

        updateTimeout();

        debugs(93, 3, "read " << rd.size << " bytes");

        disableRetries(); // because pconn did not fail

        /* Continue to process previously read data */
        break;

    case Comm::ENDFILE: // close detected by 0-byte read
        commEof = true;
        reuseConnection = false;

        // detect a pconn race condition: eof on the first pconn read
        if (!al.icap.bytesRead && retriable()) {
            setOutcome(xoRace);
            mustStop("pconn race");
            return;
        }

        break;

    // case Comm::COMM_ERROR:
    default: // no other flags should ever occur
        debugs(11, 2, io.conn << ": read failure: " << xstrerr(rd.xerrno));
        mustStop("unknown ICAP I/O read error");
        return;
    }

    handleCommRead(io.size);
}

void Adaptation::Icap::Xaction::cancelRead()
{
    if (reader != NULL) {
        Must(haveConnection());
        Comm::ReadCancel(connection->fd, reader);
        reader = NULL;
    }
}

bool
Adaptation::Icap::Xaction::parseHttpMsg(Http::Message *msg)
{
    debugs(93, 5, "have " << readBuf.length() << " head bytes to parse");

    Http::StatusCode error = Http::scNone;
    // XXX: performance regression c_str() data copies
    const char *buf = readBuf.c_str();
    const bool parsed = msg->parse(buf, readBuf.length(), commEof, &error);
    Must(parsed || !error); // success or need more data

    if (!parsed) {  // need more data
        Must(mayReadMore());
        msg->reset();
        return false;
    }

    readBuf.consume(msg->hdr_sz);
    return true;
}

bool Adaptation::Icap::Xaction::mayReadMore() const
{
    return !doneReading() && // will read more data
           readBuf.length() < SQUID_TCP_SO_RCVBUF;  // have space for more data
}

bool Adaptation::Icap::Xaction::doneReading() const
{
    return commEof;
}

bool Adaptation::Icap::Xaction::doneWriting() const
{
    return !writer;
}

bool Adaptation::Icap::Xaction::doneWithIo() const
{
    return haveConnection() &&
           !transportWait && !reader && !writer && // fast checks, some redundant
           doneReading() && doneWriting();
}

bool Adaptation::Icap::Xaction::haveConnection() const
{
    return connection != NULL && connection->isOpen();
}

// initiator aborted
void Adaptation::Icap::Xaction::noteInitiatorAborted()
{

    if (theInitiator.set()) {
        debugs(93,4, HERE << "Initiator gone before ICAP transaction ended");
        clearInitiator();
        detailError(ERR_DETAIL_ICAP_INIT_GONE);
        setOutcome(xoGone);
        mustStop("initiator aborted");
    }

}

void Adaptation::Icap::Xaction::setOutcome(const Adaptation::Icap::XactOutcome &xo)
{
    if (al.icap.outcome != xoUnknown) {
        debugs(93, 3, "WARNING: resetting outcome: from " << al.icap.outcome << " to " << xo);
    } else {
        debugs(93, 4, HERE << xo);
    }
    al.icap.outcome = xo;
}

// This 'last chance' method is called before a 'done' transaction is deleted.
// It is wrong to call virtual methods from a destructor. Besides, this call
// indicates that the transaction will terminate as planned.
void Adaptation::Icap::Xaction::swanSong()
{
    // kids should sing first and then call the parent method.
    if (transportWait || encryptionWait) {
        service().noteConnectionFailed("abort");
    }

    closeConnection(); // TODO: rename because we do not always close

    readBuf.clear();

    tellQueryAborted();

    maybeLog();

    Adaptation::Initiate::swanSong();
}

void Adaptation::Icap::Xaction::tellQueryAborted()
{
    if (theInitiator.set()) {
        Adaptation::Icap::XactAbortInfo abortInfo(icapRequest, icapReply.getRaw(),
                retriable(), repeatable());
        Launcher *launcher = dynamic_cast<Launcher*>(theInitiator.get());
        // launcher may be nil if initiator is invalid
        CallJobHere1(91,5, CbcPointer<Launcher>(launcher),
                     Launcher, noteXactAbort, abortInfo);
        clearInitiator();
    }
}

void Adaptation::Icap::Xaction::maybeLog()
{
    if (IcapLogfileStatus == LOG_ENABLE) {
        finalizeLogInfo();
        icapLogLog(alep);
    }
}

void Adaptation::Icap::Xaction::finalizeLogInfo()
{
    //prepare log data
    al.icp.opcode = ICP_INVALID;

    const Adaptation::Icap::ServiceRep &s = service();
    al.icap.hostAddr = s.cfg().host.termedBuf();
    al.icap.serviceName = s.cfg().key;
    al.icap.reqUri = s.cfg().uri;

    tvSub(al.icap.ioTime, icap_tio_start, icap_tio_finish);
    tvSub(al.icap.trTime, icap_tr_start, current_time);

    al.icap.request = icapRequest;
    HTTPMSGLOCK(al.icap.request);
    if (icapReply != NULL) {
        al.icap.reply = icapReply.getRaw();
        HTTPMSGLOCK(al.icap.reply);
        al.icap.resStatus = icapReply->sline.status();
    }
}

// returns a temporary string depicting transaction status, for debugging
const char *Adaptation::Icap::Xaction::status() const
{
    static MemBuf buf;
    buf.reset();
    buf.append(" [", 2);
    fillPendingStatus(buf);
    buf.append("/", 1);
    fillDoneStatus(buf);
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}

void Adaptation::Icap::Xaction::fillPendingStatus(MemBuf &buf) const
{
    if (haveConnection()) {
        buf.appendf("FD %d", connection->fd);

        if (writer != NULL)
            buf.append("w", 1);

        if (reader != NULL)
            buf.append("r", 1);

        buf.append(";", 1);
    }
}

void Adaptation::Icap::Xaction::fillDoneStatus(MemBuf &buf) const
{
    if (haveConnection() && commEof)
        buf.appendf("Comm(%d)", connection->fd);

    if (stopReason != NULL)
        buf.append("Stopped", 7);
}

bool Adaptation::Icap::Xaction::fillVirginHttpHeader(MemBuf &) const
{
    return false;
}

bool
Ssl::IcapPeerConnector::initialize(Security::SessionPointer &serverSession)
{
    if (!Security::PeerConnector::initialize(serverSession))
        return false;

    assert(!icapService->cfg().secure.sslDomain.isEmpty());
#if USE_OPENSSL
    SBuf *host = new SBuf(icapService->cfg().secure.sslDomain);
    SSL_set_ex_data(serverSession.get(), ssl_ex_index_server, host);
    setClientSNI(serverSession.get(), host->c_str());

    ACLFilledChecklist *check = static_cast<ACLFilledChecklist *>(SSL_get_ex_data(serverSession.get(), ssl_ex_index_cert_error_check));
    if (check)
        check->dst_peer_name = *host;
#endif

    Security::SetSessionResumeData(serverSession, icapService->sslSession);
    return true;
}

void
Ssl::IcapPeerConnector::noteNegotiationDone(ErrorState *error)
{
    if (error)
        return;

    const int fd = serverConnection()->fd;
    Security::MaybeGetSessionResumeData(fd_table[fd].ssl, icapService->sslSession);
}

void
Adaptation::Icap::Xaction::handleSecuredPeer(Security::EncryptorAnswer &answer)
{
    encryptionWait.finish();

    if (answer.error.get()) {
        // XXX: Security::PeerConnector should do that for negative answers instead.
        if (answer.conn != NULL)
            answer.conn->close();
        // TODO: Refactor dieOnConnectionFailure() to be usable here as well.
        debugs(93, 2, typeName <<
               " TLS negotiation to " << service().cfg().uri << " failed");
        service().noteConnectionFailed("failure");
        detailError(ERR_DETAIL_ICAP_XACT_SSL_START);
        throw TexcHere("cannot connect to the TLS ICAP service");
    }

    debugs(93, 5, "TLS negotiation to " << service().cfg().uri << " complete");

    // XXX: answer.conn could be closing here. Missing a syncWithComm equivalent?
    useIcapConnection(answer.conn);
}

