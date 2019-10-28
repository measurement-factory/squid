/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "comm/forward.h"
#include "ExternalACLEntry.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#if USE_AUTH
#include "auth/AclProxyAuth.h"
#include "auth/UserRequest.h"
#endif

CBDATA_CLASS_INIT(ACLFilledChecklist);

ACLFilledChecklist::ACLFilledChecklist() :
    dst_rdns(NULL),
    request (NULL),
    reply (NULL),
#if USE_AUTH
    auth_user_request (NULL),
#endif
#if SQUID_SNMP
    snmp_community(NULL),
#endif
#if USE_OPENSSL
    sslErrors(NULL),
#endif
    requestErrorType(ERR_MAX),
    connectionManager_(nullptr),
    fd_(-1),
    destinationDomainChecked_(false),
    sourceDomainChecked_(false)
{
    my_addr.setEmpty();
    client_addr.setEmpty();
    dst_addr.setEmpty();
    rfc931[0] = '\0';
}

ACLFilledChecklist::~ACLFilledChecklist()
{
    assert (!asyncInProgress());

    safe_free(dst_rdns); // created by xstrdup().

    HTTPMSGUNLOCK(request);

    HTTPMSGUNLOCK(reply);

    cbdataReferenceDone(connectionManager_);

#if USE_OPENSSL
    cbdataReferenceDone(sslErrors);
#endif

    debugs(28, 4, HERE << "ACLFilledChecklist destroyed " << this);
}

static void
showDebugWarning(const char *msg)
{
    static uint16_t count = 0;
    if (count > 10)
        return;

    ++count;
    debugs(28, DBG_IMPORTANT, "ALE missing " << msg);
}

void
ACLFilledChecklist::verifyAle() const
{
    // make sure the ALE fields used by Format::assemble to
    // fill the old external_acl_type codes are set if any
    // data on them exists in the Checklist

    if (!al->cache.port) {
        if (const auto mgr = clientConnectionManager()) {
            showDebugWarning("listening port");
            al->cache.port = mgr->port;
        }
    }

    if (request) {
        if (!al->request) {
            showDebugWarning("HttpRequest object");
            // XXX: al->request should be original,
            // but the request may be already adapted
            al->request = request;
            HTTPMSGLOCK(al->request);
        }

        if (!al->adapted_request) {
            showDebugWarning("adapted HttpRequest object");
            al->adapted_request = request;
            HTTPMSGLOCK(al->adapted_request);
        }

        if (al->url.isEmpty()) {
            showDebugWarning("URL");
            // XXX: al->url should be the request URL from client,
            // but request->url may be different (e.g.,redirected)
            al->url = request->effectiveRequestUri();
        }
    }

    if (reply && !al->reply) {
        showDebugWarning("HttpReply object");
        al->reply = reply;
        HTTPMSGLOCK(al->reply);
    }

#if USE_IDENT
    if (*rfc931 && !al->cache.rfc931) {
        showDebugWarning("IDENT");
        al->cache.rfc931 = xstrdup(rfc931);
    }
#endif
}

void
ACLFilledChecklist::syncAle(HttpRequest *adaptedRequest, const char *logUri) const
{
    if (!al)
        return;
    if (adaptedRequest && !al->adapted_request) {
        al->adapted_request = adaptedRequest;
        HTTPMSGLOCK(al->adapted_request);
    }
    if (logUri && al->url.isEmpty())
        al->url = logUri;
}

ConnStateData *
ACLFilledChecklist::clientConnectionManager() const
{
    return cbdataReferenceValid(connectionManager_) ? connectionManager_ : nullptr;
}

#if FOLLOW_X_FORWARDED_FOR
void
ACLFilledChecklist::preferIndirectAddr()
{
    assert(request);
    client_addr = al->furthestClientAddress();
}
#endif

void
ACLFilledChecklist::forceDirectAddr()
{
    assert(request);
    client_addr = al->clientAddr();
}

int
ACLFilledChecklist::fd() const
{
    const auto c = clientConnectionManager();
    return (c && c->clientConnection) ? c->clientConnection->fd : fd_;
}

void
ACLFilledChecklist::fd(int aDescriptor)
{
    const auto c = clientConnectionManager();
    assert(!c || !c->clientConnection || c->clientConnection->fd == aDescriptor);
    fd_ = aDescriptor;
}

bool
ACLFilledChecklist::destinationDomainChecked() const
{
    return destinationDomainChecked_;
}

void
ACLFilledChecklist::markDestinationDomainChecked()
{
    assert (!finished() && !destinationDomainChecked());
    destinationDomainChecked_ = true;
}

bool
ACLFilledChecklist::sourceDomainChecked() const
{
    return sourceDomainChecked_;
}

void
ACLFilledChecklist::markSourceDomainChecked()
{
    assert (!finished() && !sourceDomainChecked());
    sourceDomainChecked_ = true;
}

/*
 * There are two common ACLFilledChecklist lifecycles paths:
 *
 * A) Using aclCheckFast(): The caller creates an ACLFilledChecklist object
 *    on stack and calls aclCheckFast().
 *
 * B) Using aclNBCheck() and callbacks: The caller allocates an
 *    ACLFilledChecklist object (via operator new) and passes it to
 *    aclNBCheck(). Control eventually passes to ACLChecklist::checkCallback(),
 *    which will invoke the callback function as requested by the
 *    original caller of aclNBCheck().  This callback function must
 *    *not* delete the list.  After the callback function returns,
 *    checkCallback() will delete the list (i.e., self).
 */
ACLFilledChecklist::ACLFilledChecklist(const acl_access *A, HttpRequest *http_request, const AccessLogEntry::Pointer &ale, const char *ident):
    dst_rdns(NULL),
    request(NULL),
    reply(NULL),
#if USE_AUTH
    auth_user_request(NULL),
#endif
#if SQUID_SNMP
    snmp_community(NULL),
#endif
#if USE_OPENSSL
    sslErrors(NULL),
#endif
    al(ale),
    requestErrorType(ERR_MAX),
    connectionManager_(nullptr),
    fd_(-1),
    destinationDomainChecked_(false),
    sourceDomainChecked_(false)
{
    my_addr.setEmpty();
    client_addr.setEmpty();
    dst_addr.setEmpty();
    rfc931[0] = '\0';

    changeAcl(A);
    setRequest(http_request);
    setIdent(ident);
}

void ACLFilledChecklist::setRequest(HttpRequest *httpRequest)
{
    assert(!request);
    if (httpRequest) {
        request = httpRequest;
        HTTPMSGLOCK(request);
        setClientConnectionDetails(request->clientConnectionManager().get());
        if (!clientConnectionManager()) // could not take the connection from the connection manager
            setClientConnection(al->tcpClient);
    }
}

static void
InitializeClientAddress(Ip::Address &addr, const Ip::Address &value)
{
    assert(!addr.isKnown() || addr == value);
    if (!addr.isKnown())
        addr = value;
}

/// configures addresses of the client-to-Squid connection
void
ACLFilledChecklist::setClientSideAddresses()
{
    if (request) {
#if FOLLOW_X_FORWARDED_FOR
        if (Config.onoff.acl_uses_indirect_client)
            InitializeClientAddress(client_addr, al->furthestClientAddress());
        else
#endif
            InitializeClientAddress(client_addr, al->clientAddr());
        InitializeClientAddress(my_addr, al->myAddr());
    } else if (clientConnection_) {
        InitializeClientAddress(client_addr, clientConnection_->remote);
        InitializeClientAddress(my_addr, clientConnection_->local);
    }
}

void
ACLFilledChecklist::setClientConnectionDetails(ConnStateData *mgr, Comm::ConnectionPointer conn)
{
    if (clientConnectionManager())
        return;

    if (mgr && cbdataReferenceValid(mgr)) {
        connectionManager_ = cbdataReference(mgr);
        Must(!conn || conn == mgr->clientConnection);
        setClientConnection(mgr->clientConnection);
        return;
    }

    setClientConnection(conn);
}

/// Configures client-related fields from the passed client connection.
/// Has no effect if the fields are already initialized.
void
ACLFilledChecklist::setClientConnection(Comm::ConnectionPointer conn)
{
    if (!conn)
        return;

    if (clientConnection_) {
        Must(conn == clientConnection_);
        return;
    }

    clientConnection_ = conn;

    setClientSideAddresses();
}

void
ACLFilledChecklist::snmpDetails(char *snmpCommunity, const Ip::Address &fromAddr, const Ip::Address &localAddr)
{
    snmp_community = snmpCommunity;
    client_addr = fromAddr;
    my_addr = localAddr;
}

void
ACLFilledChecklist::setIdent(const char *ident)
{
#if USE_IDENT
    assert(!rfc931[0]);
    if (ident)
        xstrncpy(rfc931, ident, USER_IDENT_SZ);
#endif
}

