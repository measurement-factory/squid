/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#ifndef SQUID_SRC_CLIENT_SIDE_H
#define SQUID_SRC_CLIENT_SIDE_H

#include "acl/ChecklistFiller.h"
#include "anyp/forward.h"
#include "anyp/ProtocolVersion.h"
#include "base/AsyncJob.h"
#include "base/RunnersRegistry.h"
#include "BodyPipe.h"
#include "comm.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "error/Error.h"
#include "error/forward.h"
#include "helper/forward.h"
#include "http/forward.h"
#include "http/Stream.h"
#include "HttpControlMsg.h"
#include "ipc/FdNotes.h"
#include "log/forward.h"
#include "Pipeline.h"
#include "proxyp/forward.h"
#include "sbuf/SBuf.h"
#include "servers/forward.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#include "security/KeyLogger.h"
#if USE_OPENSSL
#include "security/forward.h"
#include "security/Handshake.h"
#include "ssl/support.h"
#endif
#if USE_DELAY_POOLS
#include "MessageBucket.h"
#endif

#include <iosfwd>

class ClientHttpRequest;
class HttpHdrRangeSpec;

class MasterXaction;
typedef RefCount<MasterXaction> MasterXactionPointer;

#if USE_OPENSSL
namespace Ssl
{
class ServerBump;
}
#endif

/**
 * Legacy Server code managing a connection to a client.
 *
 * NP: presents AsyncJob API but does not operate autonomously as a Job.
 *     So Must() is not safe to use.
 *
 * Multiple requests (up to pipeline_prefetch) can be pipelined.
 * This object is responsible for managing which one is currently being
 * fulfilled and what happens to the queue if the current one causes the client
 * connection to be closed early.
 *
 * Act as a manager for the client connection and passes data in buffer to a
 * Parser relevant to the state (message headers vs body) that is being
 * processed.
 *
 * Performs HTTP message processing to kick off the actual HTTP request
 * handling objects (Http::Stream, ClientHttpRequest, HttpRequest).
 *
 * Performs SSL-Bump processing for switching between HTTP and HTTPS protocols.
 *
 * To terminate a ConnStateData close() the client Comm::Connection it is
 * managing, or for graceful half-close use the stopReceiving() or
 * stopSending() methods.
 */
class ConnStateData:
    virtual public AsyncJob,
    public BodyProducer,
    public HttpControlMsgSink,
    public Acl::ChecklistFiller,
    private IndependentRunner
{

public:
    explicit ConnStateData(const MasterXactionPointer &xact);
    ~ConnStateData() override;

    /// maybe grow the inBuf and schedule Comm::Read()
    void readSomeData();

    /// cancels Comm::Read() if it is scheduled
    void stopReading();

    /// schedule some data for a Comm::Write()
    void write(MemBuf *mb);

    /// schedule some data for a Comm::Write()
    void write(char *buf, int len);

public:
    /* HttpControlMsgSink API */
    void sendControlMsg(HttpControlMsg) override;
    void doneWithControlMsg() override;

    /// Traffic parsing
    void readNextRequest();

    /// try to make progress on a transaction or read more I/O
    void kick();

    bool isOpen() const;

    Http1::TeChunkedParser *bodyParser = nullptr; ///< parses HTTP/1.1 chunked request body

    /** number of body bytes we need to comm_read for the "current" request
     *
     * \retval 0         We do not need to read any [more] body bytes
     * \retval negative  May need more but do not know how many; could be zero!
     * \retval positive  Need to read exactly that many more body bytes
     */
    int64_t mayNeedToReadMoreBody() const;

#if USE_AUTH
    /**
     * Fetch the user details for connection based authentication
     * NOTE: this is ONLY connection based because NTLM and Negotiate is against HTTP spec.
     */
    const Auth::UserRequest::Pointer &getAuth() const { return auth_; }

    /**
     * Set the user details for connection-based authentication to use from now until connection closure.
     *
     * Any change to existing credentials shows that something invalid has happened. Such as:
     * - NTLM/Negotiate auth was violated by the per-request headers missing a revalidation token
     * - NTLM/Negotiate auth was violated by the per-request headers being for another user
     * - SSL-Bump CONNECT tunnel with persistent credentials has ended
     */
    void setAuth(const Auth::UserRequest::Pointer &aur, const char *cause);
#endif

    Ip::Address log_addr;

    struct {
        bool readMore = true; ///< needs comm_read (for this request or new requests)
        bool swanSang = false; // XXX: temporary flag to check proper cleanup
    } flags;
    struct {
        Comm::ConnectionPointer serverConnection; /* pinned server side connection */
        char *host = nullptr; ///< host name of pinned connection
        AnyP::Port port; ///< destination port of the request that caused serverConnection
        bool pinned = false; ///< this connection was pinned
        bool auth = false; ///< pinned for www authentication
        bool reading = false; ///< we are monitoring for peer connection closure
        bool zeroReply = false; ///< server closed w/o response (ERR_ZERO_SIZE_OBJECT)
        bool peerAccessDenied = false; ///< cache_peer_access denied pinned connection reuse
        CachePeer *peer() const { return serverConnection ? serverConnection->getPeer() : nullptr; }
        AsyncCall::Pointer readHandler; ///< detects serverConnection closure
        AsyncCall::Pointer closeHandler; ///< The close handler for pinned server side connection
    } pinning;

    bool transparent() const;

    /// true if we stopped receiving the request
    const char *stoppedReceiving() const { return stoppedReceiving_; }
    /// true if we stopped sending the response
    const char *stoppedSending() const { return stoppedSending_; }
    /// note request receiving error and close as soon as we write the response
    void stopReceiving(const char *error);
    /// note response sending error and close as soon as we read the request
    void stopSending(const char *error);

    /// (re)sets timeout for receiving more bytes from the client
    void resetReadTimeout(time_t timeout);
    /// (re)sets client_lifetime timeout
    void extendLifetime();

    void expectNoForwarding(); ///< cleans up virgin request [body] forwarding state

    /* BodyPipe API */
    BodyPipe::Pointer expectRequestBody(int64_t size);
    void noteMoreBodySpaceAvailable(BodyPipe::Pointer) override = 0;
    void noteBodyConsumerAborted(BodyPipe::Pointer) override = 0;

    bool handleRequestBodyData();

    /// parameters for the async notePinnedConnectionBecameIdle() call
    class PinnedIdleContext
    {
    public:
        PinnedIdleContext(const Comm::ConnectionPointer &conn, const HttpRequest::Pointer &req): connection(conn), request(req) {}

        Comm::ConnectionPointer connection; ///< to-server connection to be pinned
        HttpRequest::Pointer request; ///< to-server request that initiated serverConnection
    };

    /// Called when a pinned connection becomes available for forwarding the next request.
    void notePinnedConnectionBecameIdle(PinnedIdleContext pic);
    /// Forward future client requests using the given to-server connection.
    /// The connection is still being used by the current client request.
    void pinBusyConnection(const Comm::ConnectionPointer &pinServerConn, const HttpRequest::Pointer &request);
    /// Undo pinConnection() and, optionally, close the pinned connection.
    void unpinConnection(const bool andClose);

    /// \returns validated pinned to-server connection, stopping its monitoring
    /// \throws a newly allocated ErrorState if validation fails
    static Comm::ConnectionPointer BorrowPinnedConnection(HttpRequest *, const AccessLogEntryPointer &);
    /// \returns the pinned CachePeer if one exists, nil otherwise
    CachePeer *pinnedPeer() const { return pinning.peer(); }
    bool pinnedAuth() const {return pinning.auth;}

    /// called just before a FwdState-dispatched job starts using connection
    virtual void notePeerConnection(Comm::ConnectionPointer) {}

    // pining related comm callbacks
    virtual void clientPinnedConnectionClosed(const CommCloseCbParams &io);

    /// noteTakeServerConnectionControl() callback parameter
    class ServerConnectionContext {
    public:
        ServerConnectionContext(const Comm::ConnectionPointer &conn, const SBuf &post101Bytes) : preReadServerBytes(post101Bytes), conn_(conn) { conn_->enterOrphanage(); }

        /// gives to-server connection to the new owner
        Comm::ConnectionPointer connection() { conn_->leaveOrphanage(); return conn_; }

        SBuf preReadServerBytes; ///< post-101 bytes received from the server

    private:
        friend std::ostream &operator <<(std::ostream &, const ServerConnectionContext &);
        Comm::ConnectionPointer conn_; ///< to-server connection
    };

    /// Gives us the control of the Squid-to-server connection.
    /// Used, for example, to initiate a TCP tunnel after protocol switching.
    virtual void noteTakeServerConnectionControl(ServerConnectionContext) {}

    // comm callbacks
    void clientReadFtpData(const CommIoCbParams &io);
    void connStateClosed(const CommCloseCbParams &io);
    void requestTimeout(const CommTimeoutCbParams &params);
    void lifetimeTimeout(const CommTimeoutCbParams &params);

    // AsyncJob API
    void start() override;
    bool doneAll() const override { return BodyProducer::doneAll() && false;}
    void swanSong() override;
    void callException(const std::exception &) override;

    /// Changes state so that we close the connection and quit after serving
    /// the client-side-detected error response instead of getting stuck.
    void quitAfterError(HttpRequest *request); // meant to be private

    /// The caller assumes responsibility for connection closure detection.
    void stopPinnedConnectionMonitoring();

    /// Starts or resumes accepting a TLS connection. TODO: Make this helper
    /// method protected after converting clientNegotiateSSL() into a method.
    Security::IoResult acceptTls();

    /// the second part of old httpsAccept, waiting for future HttpsServer home
    void postHttpsAccept();

#if USE_OPENSSL
    /// Initializes and starts a peek-and-splice negotiation with the SSL client
    void startPeekAndSplice();

    /// Called when a peek-and-splice step finished. For example after
    /// server SSL certificates received and fake server SSL certificates
    /// generated
    void doPeekAndSpliceStep();
    /// called by FwdState when it is done bumping the server
    void httpsPeeked(PinnedIdleContext pic);

    /// Splice a bumped client connection on peek-and-splice mode
    bool splice();

    /// Start to create dynamic Security::ContextPointer for host or uses static port SSL context.
    void getSslContextStart();

    /// finish configuring the newly created SSL context"
    void getSslContextDone(Security::ContextPointer &);

    /// Callback function. It is called when squid receive message from ssl_crtd.
    static void sslCrtdHandleReplyWrapper(void *data, const Helper::Reply &reply);
    /// Process response from ssl_crtd.
    void sslCrtdHandleReply(const Helper::Reply &reply);

    void switchToHttps(ClientHttpRequest *, Ssl::BumpMode bumpServerMode);
    void parseTlsHandshake();
    bool switchedToHttps() const { return switchedToHttps_; }
    Ssl::ServerBump *serverBump() {return sslServerBump;}
    inline void setServerBump(Ssl::ServerBump *srvBump) {
        if (!sslServerBump)
            sslServerBump = srvBump;
        else
            assert(sslServerBump == srvBump);
    }
    const SBuf &sslCommonName() const {return sslCommonName_;}
    void resetSslCommonName(const char *name) {sslCommonName_ = name;}
    const SBuf &tlsClientSni() const { return tlsClientSni_; }
    /// Fill the certAdaptParams with the required data for certificate adaptation
    /// and create the key for storing/retrieve the certificate to/from the cache
    void buildSslCertGenerationParams(Ssl::CertificateProperties &certProperties);
    /// Called when the client sends the first request on a bumped connection.
    /// Returns false if no [delayed] error should be written to the client.
    /// Otherwise, writes the error to the client and returns true. Also checks
    /// for SQUID_X509_V_ERR_DOMAIN_MISMATCH on bumped requests.
    bool serveDelayedError(Http::Stream *);

    Ssl::BumpMode sslBumpMode = Ssl::bumpEnd; ///< ssl_bump decision (Ssl::bumpEnd if n/a).

    /// Tls parser to use for client HELLO messages parsing on bumped
    /// connections.
    Security::HandshakeParser tlsParser;
#else
    bool switchedToHttps() const { return false; }
#endif
    char *prepareTlsSwitchingURL(const Http1::RequestParserPointer &hp);

    /// registers a newly created stream
    void add(const Http::StreamPointer &context);

    /// handle a control message received by context from a peer and call back
    virtual bool writeControlMsgAndCall(HttpReply *rep, AsyncCall::Pointer &call) = 0;

    /// Handle response header (once) and data for the current Http::Stream.
    /// This interface allows Http::Stream::handleStoreReply() (which does not
    /// and should not do FTP) to reach our Ftp::Server child (which does). It
    /// should disappear as we solve "FTP code is forced to use an HTTP-focused
    /// class" problems detailed in Http::Stream class description.
    virtual void handleReply(HttpReply *header, StoreIOBuffer receivedData) = 0;

    /// remove no longer needed leading bytes from the input buffer
    void consumeInput(const size_t byteCount);

    /* TODO: Make the methods below (at least) non-public when possible. */

    /// stop parsing the request and create context for relaying error info
    Http::Stream *abortRequestParsing(const char *const errUri);

    /// generate a fake CONNECT request with the given payload
    /// at the beginning of the client I/O buffer
    bool fakeAConnectRequest(const char *reason, const SBuf &payload);

    /// generates and sends to tunnel.cc a fake request with a given payload
    bool initiateTunneledRequest(HttpRequest::Pointer const &cause, const char *reason, const SBuf &payload);

    /// whether we should start saving inBuf client bytes in anticipation of
    /// tunneling them to the server later (on_unsupported_protocol)
    bool shouldPreserveClientData() const;

    /// build a fake http request
    ClientHttpRequest *buildFakeRequest(SBuf &useHost, AnyP::KnownPort usePort, const SBuf &payload);

    /// From-client handshake bytes (including bytes at the beginning of a
    /// CONNECT tunnel) which we may need to forward as-is if their syntax does
    /// not match the expected TLS or HTTP protocol (on_unsupported_protocol).
    SBuf preservedClientData;

    /* Registered Runner API */
    void startShutdown() override;
    void endingShutdown() override;

    /// \returns existing non-empty connection annotations,
    /// creates and returns empty annotations otherwise
    NotePairs::Pointer notes();
    bool hasNotes() const { return bool(theNotes) && !theNotes->empty(); }

    const ProxyProtocol::HeaderPointer &proxyProtocolHeader() const { return proxyProtocolHeader_; }

    /// if necessary, stores new error information (if any)
    void updateError(const Error &);

    /// emplacement/convenience wrapper for updateError(const Error &)
    void updateError(const err_type c, const ErrorDetailPointer &d) { updateError(Error(c, d)); }

    /* Acl::ChecklistFiller API */
    void fillChecklist(ACLFilledChecklist &) const override;

    /// fillChecklist() obligations not fulfilled by the front request
    /// TODO: This is a temporary ACLFilledChecklist::setConn() callback to
    /// allow filling checklist using our non-public information sources. It
    /// should be removed as unnecessary by making ACLs extract the information
    /// they need from the ACLFilledChecklist::conn() without filling/copying.
    void fillConnectionLevelDetails(ACLFilledChecklist &) const;

    // Exposed to be accessible inside the ClientHttpRequest constructor.
    // TODO: Remove. Make sure there is always a suitable ALE instead.
    /// a problem that occurred without a request (e.g., while parsing headers)
    Error bareError;

    /// managers logging of the being-accepted TLS connection secrets
    Security::KeyLogger keyLogger;

// XXX: should be 'protected:' for child access only,
//      but all sorts of code likes to play directly
//      with the I/O buffers and socket.
public:
    // Client TCP connection details from comm layer.
    Comm::ConnectionPointer clientConnection;

    /**
     * The transfer protocol currently being spoken on this connection.
     * HTTP/1.x CONNECT, HTTP/1.1 Upgrade and HTTP/2 SETTINGS offer the
     * ability to change protocols on the fly.
     */
    AnyP::ProtocolVersion transferProtocol;

    /// Squid listening port details where this connection arrived.
    AnyP::PortCfgPointer port;

    /// read I/O buffer for the client connection
    SBuf inBuf;

    /// set of requests waiting to be serviced
    Pipeline pipeline;

protected:
    /// whether client_request_buffer_max_size allows inBuf.length() increase
    bool mayBufferMoreRequestBytes() const;

    void startDechunkingRequest();
    void finishDechunkingRequest(bool withSuccess);
    void abortChunkedRequestBody(const err_type error);
    err_type handleChunkedRequestBody();

    /// ConnStateData-specific part of BorrowPinnedConnection()
    Comm::ConnectionPointer borrowPinnedConnection(HttpRequest *, const AccessLogEntryPointer &);

    void startPinnedConnectionMonitoring();
    void clientPinnedConnectionRead(const CommIoCbParams &io);
#if USE_OPENSSL
    /// Handles a ready-for-reading TLS squid-to-server connection that
    /// we thought was idle.
    /// \return false if and only if the connection should be closed.
    bool handleIdleClientPinnedTlsRead();
#endif

    /// Parse an HTTP request
    /// \note Sets result->flags.parsed_ok to 0 if failed to parse the request,
    ///       to 1 if the request was correctly parsed
    /// \param[in] hp an Http1::RequestParser
    /// \return NULL on incomplete requests,
    ///         a Http::Stream on success or failure.
    /// TODO: Move to HttpServer. Warning: Move requires large code nonchanges!
    Http::Stream *parseHttpRequest(const Http1::RequestParserPointer &);

    /// parse input buffer prefix into a single transfer protocol request
    /// return NULL to request more header bytes (after checking any limits)
    /// use abortRequestParsing() to handle parsing errors w/o creating request
    virtual Http::Stream *parseOneRequest() = 0;

    /// start processing a freshly parsed request
    virtual void processParsedRequest(Http::StreamPointer &) = 0;

    /// returning N allows a pipeline of 1+N requests (see pipeline_prefetch)
    virtual int pipelinePrefetchMax() const;

    /// timeout to use when waiting for the next request
    virtual time_t idleTimeout() const = 0;

    /// Perform client data lookups that depend on client src-IP.
    /// The PROXY protocol may require some data input first.
    void whenClientIpKnown();

    BodyPipe::Pointer bodyPipe; ///< set when we are reading request body

    /// whether preservedClientData is valid and should be kept up to date
    bool preservingClientData_ = false;

    bool tunnelOnError(const err_type);

    AsyncCall::Pointer reader; ///< set when we are reading
    AsyncCall::Pointer writer; ///< set when we are writing

private:
    void terminateAll(const Error &, const LogTagsErrors &);
    bool shouldCloseOnEof() const;
    void doClientRead(const CommIoCbParams &);
    void clientWriteDone(const CommIoCbParams &);
    void maybeMakeSpaceAvailable();

    /// whether Comm::Read() is scheduled
    bool reading() const { return reader != nullptr; }

    /// whether Comm::Write() is scheduled
    bool writing() const { return writer != nullptr; }

    void checkLogging();

    void parseRequests();
    void clientAfterReadingRequests();
    bool concurrentRequestQueueFilled() const;

    void pinConnection(const Comm::ConnectionPointer &pinServerConn, const HttpRequest &request);

    void receivedFirstByte();
    bool handleReadData();
    void afterClientRead();
    void afterClientWrite(size_t);

    /* PROXY protocol functionality */
    bool proxyProtocolValidateClient();
    bool parseProxyProtocolHeader();
    bool proxyProtocolError(const char *reason);

#if USE_OPENSSL
    /// \returns a pointer to the matching cached TLS context or nil
    Security::ContextPointer getTlsContextFromCache(const SBuf &cacheKey, const Ssl::CertificateProperties &certProperties);

    /// Attempts to add a given TLS context to the cache, replacing the old
    /// same-key context, if any
    void storeTlsContextToCache(const SBuf &cacheKey, Security::ContextPointer &ctx);
    void handleSslBumpHandshakeError(const Security::IoResult &);
#endif

    /// whether PROXY protocol header is still expected
    bool needProxyProtocolHeader_ = false;

    /// the parsed PROXY protocol header
    ProxyProtocol::HeaderPointer proxyProtocolHeader_;

#if USE_AUTH
    /// some user details that can be used to perform authentication on this connection
    Auth::UserRequest::Pointer auth_;
#endif

#if USE_OPENSSL
    bool switchedToHttps_ = false;
    bool parsingTlsHandshake = false; ///< whether we are getting/parsing TLS Hello bytes
    /// The number of parsed HTTP requests headers on a bumped client connection
    uint64_t parsedBumpedRequestCount = 0;

    // TODO: Replace tlsConnectHostOrIp and tlsConnectPort with CONNECT request AnyP::Uri
    /// The TLS server host name appears in CONNECT request or the server ip address for the intercepted requests
    SBuf tlsConnectHostOrIp; ///< The TLS server host name as passed in the CONNECT request
    AnyP::Port tlsConnectPort; ///< The TLS server port number as passed in the CONNECT request
    SBuf sslCommonName_; ///< CN name for SSL certificate generation

    /// TLS client delivered SNI value. Empty string if none has been received.
    SBuf tlsClientSni_;
    SBuf sslBumpCertKey; ///< Key to use to store/retrieve generated certificate

    /// HTTPS server cert. fetching state for bump-ssl-server-first
    Ssl::ServerBump *sslServerBump = nullptr;
    Ssl::CertSignAlgorithm signAlgorithm = Ssl::algSignTrusted; ///< The signing algorithm to use
#endif

    bool receivedFirstByte_; ///< true if at least one byte received on this connection

    /// the reason why we no longer write the response or nil
    const char *stoppedSending_ = nullptr;
    /// the reason why we no longer read the request or nil
    const char *stoppedReceiving_ = nullptr;
    /// Connection annotations, clt_conn_tag and other tags are stored here.
    /// If set, are propagated to the current and all future master transactions
    /// on the connection.
    NotePairs::Pointer theNotes;
};

const char *findTrailingHTTPVersion(const char *uriAndHTTPVersion, const char *end = nullptr);

int varyEvaluateMatch(StoreEntry * entry, HttpRequest * req);

/// accept requests to a given port and inform subCall about them
void clientStartListeningOn(AnyP::PortCfgPointer &port, const RefCount< CommCbFunPtrCallT<CommAcceptCbPtrFun> > &subCall, const Ipc::FdNoteId noteId);

void clientOpenListenSockets(void);
void clientConnectionsClose(void);
void httpRequestFree(void *);

/// decide whether to expect multiple requests on the corresponding connection
void clientSetKeepaliveFlag(ClientHttpRequest *http);

/// append a "part" HTTP header (as in a multi-part/range reply) to the buffer
void clientPackRangeHdr(const HttpReplyPointer &, const HttpHdrRangeSpec *, String boundary, MemBuf *);

/// put terminating boundary for multiparts to the buffer
void clientPackTermBound(String boundary, MemBuf *);

void clientProcessRequest(ConnStateData *, const Http1::RequestParserPointer &, Http::Stream *);
void clientProcessRequestFinished(ConnStateData *, const HttpRequest::Pointer &);
void clientPostHttpsAccept(ConnStateData *);

std::ostream &operator <<(std::ostream &os, const ConnStateData::PinnedIdleContext &pic);
std::ostream &operator <<(std::ostream &, const ConnStateData::ServerConnectionContext &);

#endif /* SQUID_SRC_CLIENT_SIDE_H */

