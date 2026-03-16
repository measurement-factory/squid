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
    debugs(3, 7, "constructed, this=" << (void*)this << " hostname=" << hostname);
}

CachePeer::~CachePeer()
{
    debugs(3, 7, "destructing, this=" << (void*)this);

    xfree(name);
    xfree(host);

    while (NeighborTypeDomainList *l = typelist) {
        typelist = l->next;
        xfree(l->domain);
        delete l;
    }

    aclDestroyAccessList(&access);

#if USE_CACHE_DIGESTS
    delete digest;
    xfree(digest_url);
#endif

    xfree(login);

    // A standby.mgr job (if any) would keep `this` alive, so it has to be gone
    // now; standby.pool (if there was any) was managed by standby.mgr.
    assert(!standby.mgr);
    assert(!standby.pool);

    xfree(domain);
}

void
CachePeer::inherit(Configuration::SmoothReconfiguration &, const CachePeer &old)
{
    debugs(3, 7, " new " << *this << " inherits from old " << old);

    // XXX: Remove that function as unused: peerSelectResetIfChanged(sr, *this, fresh); // before we update *this

    // When annotating new CachePeer fields, use data member declaration order.

    // `index` is not a part of an individual peer configuration
    Assure(old.index);
    Assure(!index);

    Assure(strcmp(name, old.name) == 0);

    if (strcmp(host, old.host) != 0) {
        throw TextException(ToSBuf("No support for changing cache_peer hostname (yet)",
                                   Debug::Extra, "old hostname: ", old.host,
                                   Debug::Extra, "new hostname: ", host),
                            Here());
    }

    if (type != old.type) {
        throw TextException(ToSBuf("No support for changing cache_peer type (yet)",
                                   Debug::Extra, "old type: ", neighborTypeStr(&old),
                                   Debug::Extra, "new type: ", neighborTypeStr(this)),
                            Here());
    }

    // `in_addr` is derived from `addresses` and `icp.port` (see below for those
    // two field notes). Delay `in_addr` update until `addresses` are updated.

    stats = old.stats;

    if (icp.port == old.icp.port)
        icp = old.icp; // inherit `icp.version` and `icp.counts` stats
#if USE_HTCP
    if (htcp.port == old.htcp.port)
        htcp = old.htcp; // inherit `htcp.version` and `htcp.counts` stats
#endif

    if (http_port != old.http_port) {
        throw TextException(ToSBuf("No support for changing cache_peer HTTP port (yet)",
                                   Debug::Extra, "old port: ", old.http_port,
                                   Debug::Extra, "new port: ", http_port),
                            Here());
    }

    // copy old values managed by rigid neighbor_type_domain (which could not have changed)
    Assure(!typelist);
    auto tlNext = &typelist;
    for (auto tlOld = old.typelist; tlOld; tlOld = tlOld->next) {
        *tlNext = new NeighborTypeDomainList{xstrdup(tlOld->domain), tlOld->type, nullptr};
        tlNext = &(*tlNext)->next;
    }

    Assure(!access); // managed by pliable cache_peer_access

    // `options` may change
    // weight may change
    // basetime may change

    if (mcast.ttl == old.mcast.ttl) {
        mcast = old.mcast; // inherit mcast stats but ...
        mcast.flags = {}; // do not inherit peerCountMcastPeersSchedule() state
    }

#if USE_CACHE_DIGESTS
    Assure(!digest); // TODO: Remove digest as unused?
    Assure(!old.digest); // TODO: Remove digest as unused?
    Assure(!digest_url); // TODO: Remove digest_url as unused?
    Assure(!old.digest_url); // TODO: Remove digest_url as unused?
#endif

    tcp_up = old.tcp_up;
    reprobe = old.reprobe;

    // `addresses` changes are handled by peerDNSConfigure() triggered by peerDnsRefreshStart()
    // `n_addresses` changes are handled by peerDNSConfigure() triggered by peerDnsRefreshStart()

    rr_count = old.rr_count;
    testing_now = old.testing_now;

    // The following mutually-exclusive peer selection method hashes and load
    // fields are computed by CachePeers::reset() called from
    // Configuration::Component<CachePeers*>::FinishSmoothReconfiguration().
    // * `carp` fields
    // * `userhash` fields
    // * `sourcehash` fields

    // `login` is parsed

    // `connect_timeout_raw` is parsed
    // `connect_fail_limit` is parsed
    // `max_conn` is parsed

    // `standby.pool` is managed by standby.mgr (if any)
    // `standby.mgr` is synced later via PeerPoolMgr::SyncConfig() XXX
    // `standby.limit` is parsed
    // `standby.waitingForClose` is managed by standby.mgr (if any)

    // `domain` is parsed

    // `secure` is parsed
    // `sslContext` is parsed
    Assure(&tlsContext.options == &secure);
    Assure(&tlsContext.raw == &sslContext);

    // do not inherit session cache because session-related parameters may have changed
    Assure(!sslSession);

    // `front_end_https` is parsed
    // `connection_auth` is parsed
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
        PeerPoolMgr::Checkpoint(standby.mgr, "revived peer");
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
CachePeer::addIdlePinnedConnection(const AsyncCall::Pointer &callback)
{
    Assure(callback);
    Assure(!removed()); // or the caller would wait for a callback that would never be called
    const auto inserted = idlePinnedConnectionCallbacks_.insert(callback).second;
    Assure(inserted);
}

void
CachePeer::removeIdlePinnedConnection(const AsyncCall::Pointer &callback)
{
    if (callback) {
        (void)idlePinnedConnectionCallbacks_.erase(callback); // may have been removed by noteRemoval() already
        callback->cancel(__FUNCTION__);
    }
}

void
CachePeer::noteRemoval()
{
    removed_ = true;
    debugs(15, 3, *this << " notifies " << idlePinnedConnectionCallbacks_.size());
    for (const auto &callback: idlePinnedConnectionCallbacks_)
        ScheduleCallHere(callback);
    idlePinnedConnectionCallbacks_.clear();
}

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.name;
}

