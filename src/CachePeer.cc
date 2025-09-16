/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "base/PrecomputedCodeContext.h"
#include "CachePeer.h"
#include "configuration/Smooth.h"
#include "client_side.h"
#include "defines.h"
#include "neighbors.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "PeerDigest.h"
#include "PeerPoolMgr.h"
#include "PeerSelectState.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "util.h"

CBDATA_CLASS_INIT(CachePeer);

CachePeer::CachePeer(const SBuf &hostname):
    name(SBufToCstring(hostname)),
    host(SBufToCstring(hostname)),
    tlsContext(secure, sslContext),
    probeCodeContext(new PrecomputedCodeContext("cache_peer probe", ToSBuf("current cache_peer probe: ", *this)))
{
    Tolower(host); // but .name preserves original spelling
}

CachePeer::~CachePeer()
{
    xfree(name);
    xfree(host);

    while (NeighborTypeDomainList *l = typelist) {
        typelist = l->next;
        xfree(l->domain);
        xfree(l);
    }

    aclDestroyAccessList(&access);

#if USE_CACHE_DIGESTS
    delete digest;
    xfree(digest_url);
#endif

    xfree(login);

    delete standby.pool;

    xfree(domain);
}

void
CachePeer::update(Configuration::SmoothReconfiguration &sr, const CachePeer &fresh)
{
    debugs(3, 7, *this << " using " << fresh);

    peerSelectResetIfChanged(sr, *this, fresh); // before we update *this

    // When updating new fields, use data member declaration order.

    // `index` is not a part of an individual old peer config (that we update)
    Assure(index);
    Assure(!fresh.index);

    Assure(strcmp(name, fresh.name) == 0);

    if (strcmp(host, fresh.host) != 0) {
        throw TextException(ToSBuf("No support for changing cache_peer hostname (yet)",
                                   Debug::Extra, "old hostname: ", host,
                                   Debug::Extra, "new hostname: ", fresh.host),
                            Here());
    }

    if (type != fresh.type) {
        throw TextException(ToSBuf("No support for changing cache_peer type (yet)",
                                   Debug::Extra, "old type: ", neighborTypeStr(this),
                                   Debug::Extra, "new type: ", neighborTypeStr(&fresh)),
                            Here());
    }

    // `in_addr` is derived from `addresses` and `icp.port` (handled below);
    // delay `in_addr` update until `addresses` are updated

    // preserve `stats`

    icp.port = fresh.icp.port; // but preserve `icp.version` and `icp.counts` stats
#if USE_HTCP
    htcp.port = fresh.htcp.port; // but preserve `htcp.version` and `htcp.counts` stats
#endif

    if (http_port != fresh.http_port) {
        throw TextException(ToSBuf("No support for changing cache_peer HTTP port (yet)",
                                   Debug::Extra, "old port: ", http_port,
                                   Debug::Extra, "new port: ", fresh.http_port),
                            Here());
    }

    Assure(!fresh.typelist); // managed by rigid neighbor_type_domain
    Assure(!fresh.access); // managed by rigid cache_peer_access

    options.carp = fresh.options.carp;
#if USE_AUTH
    options.userhash = fresh.options.userhash;
#endif
    options.sourcehash = fresh.options.sourcehash;
    // XXX: Handle other options
    // Changing options like `originserver` is risky for transactions that check
    // such options multiple times. TODO: Support these changes after reference
    // counting CachePeer objects.
    // if (options != fresh.options) {
    //     throw TextException(ToSBuf("No support for changing certain cache_peer options (yet)",
    //                                Debug::Extra, "old options: ", options,
    //                                Debug::Extra, "new options: ", fresh.options),
    //                         Here());
    // }

    weight = fresh.weight;
    basetime = fresh.basetime;

    mcast.ttl = fresh.mcast.ttl; // but preserve mcast stats; TODO: Remove unused mcast.id?

#if USE_CACHE_DIGESTS
    Assure(!digest); // TODO: Remove digest as unused?
    Assure(!fresh.digest); // TODO: Remove digest as unused?
    Assure(!digest_url); // TODO: Remove digest_url as unused?
    Assure(!fresh.digest_url); // TODO: Remove digest_url as unused?
#endif
    // preserve `tcp_up` state
    // preserve `reprobe` state

    stale = fresh.stale;
    Assure(!stale); // update() should be given fresh configurations

    // `addresses` changes are handled by peerDNSConfigure() triggered by peerDnsRefreshStart()
    // `n_addresses` changes are handled by peerDNSConfigure() triggered by peerDnsRefreshStart()

    // preserve `rr_count` stats
    // preserve `testing_now` state

    // The mutually exclusive peer selection fields below are set (if they are
    // still relevant but need updating) via peerSelectResetIfChanged():
    // preserve `carp` fields
    // preserve `userhash` fields
    // preserve `sourcehash` fields

    // XXX: Address HttpRequest::prepForPeering() XXX first!
    // safe_free(login);
    // login = fresh.login ? xstrdup(fresh.login) : nullptr;

    connect_timeout_raw = fresh.connect_timeout_raw;
    connect_fail_limit = fresh.connect_fail_limit;
    max_conn = fresh.max_conn;

    // standby.pool is is managed by standby.mgr (if any)
    // standby.mgr is synced later via PeerPoolMgr::SyncConfig()
    standby.limit = fresh.standby.limit;
    // standby.waitingForClose is managed by standby.mgr (if any)

    // XXX: Address HttpRequest::prepForPeering() XXX first!
    // safe_free(domain);
    // domain = fresh.domain ? xstrdup(fresh.domain) : nullptr;

    secure = fresh.secure;
    sslContext = fresh.sslContext;
    Assure(&tlsContext.options == &secure);
    Assure(&tlsContext.raw == &sslContext);

    // reset session cache because session-related parameters may have changed
    sslSession = nullptr;

    front_end_https = fresh.front_end_https;
    connection_auth = fresh.connection_auth;
}

Security::FuturePeerContext *
CachePeer::securityContext()
{
    if (secure.encryptTransport)
        return &tlsContext;
    return nullptr;
}

void
CachePeer::noteSuccess()
{
    if (!tcp_up) {
        debugs(15, 2, "connection to " << *this << " succeeded");
        tcp_up = connect_fail_limit; // NP: so peerAlive() works properly.
        peerAlive(this);
    } else {
        tcp_up = connect_fail_limit;
    }
}

// TODO: Require callers to detail failures instead of using one (and often
// misleading!) "connection failed" phrase for all of them.
/// noteFailure() helper for handling failures attributed to this peer
void
CachePeer::noteFailure()
{
    stats.last_connect_failure = squid_curtime;
    if (tcp_up > 0)
        --tcp_up;

    const auto consideredAliveByAdmin = (stats.logged_state == PEER_ALIVE);
    const auto level = consideredAliveByAdmin ? DBG_IMPORTANT : 2;
    debugs(15, level, "ERROR: Connection to " << *this << " failed");

    if (consideredAliveByAdmin) {
        if (!tcp_up) {
            debugs(15, DBG_IMPORTANT, "Detected DEAD " << neighborTypeStr(this) << ": " << name);
            stats.logged_state = PEER_DEAD;
        } else {
            debugs(15, 2, "additional failures needed to mark this cache_peer DEAD: " << tcp_up);
        }
    } else {
        assert(!tcp_up);
        debugs(15, 2, "cache_peer " << *this << " is still DEAD");
    }
}

void
CachePeer::rename(const char * const newName)
{
    if (!newName || !*newName)
        throw TextException("cache_peer name=value cannot be empty", Here());

    xfree(name);
    name = xstrdup(newName);
}

time_t
CachePeer::connectTimeout() const
{
    if (connect_timeout_raw > 0)
        return connect_timeout_raw;
    return Config.Timeout.peer_connect;
}

void
CachePeer::addIdlePinnedConnection(const AsyncCall::Pointer &call)
{
    Assure(idlePinnedConnections.find(call) == idlePinnedConnections.end());
    idlePinnedConnections.insert(call);
}

void
CachePeer::removeIdlePinnedConnection(const AsyncCall::Pointer &call)
{
    const auto found = idlePinnedConnections.find(call);
    if (found != idlePinnedConnections.end())
        idlePinnedConnections.erase(found);
}

void
CachePeer::noteRemove()
{
    for (const auto &callback: idlePinnedConnections)
        ScheduleCallHere(callback);
    idlePinnedConnections.clear();
}

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.name;
}

