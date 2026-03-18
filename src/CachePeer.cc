/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "acl/Tree.h"
#include "base/IoManip.h"
#include "base/PrecomputedCodeContext.h"
#include "CachePeer.h"
#include "configuration/Smooth.h"
#include "defines.h"
#include "FwdState.h"
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
CachePeer::copyRigidFrom(const CachePeer &old)
{
    debugs(3, 7, " new " << *this << " inherits from old " << old);
    Assure(strcmp(name, old.name) == 0);

    // XXX: Remove that function as unused: peerSelectResetIfChanged(sr, *this, fresh); // before we update *this

    // TODO: Remove this copying after making neighbor_type_domain pliable.
    // Copy old values managed by rigid neighbor_type_domain (which could not have changed).
    Assure(!typelist);
    auto tlNext = &typelist;
    for (auto tlOld = old.typelist; tlOld; tlOld = tlOld->next) {
        *tlNext = new NeighborTypeDomainList{xstrdup(tlOld->domain), tlOld->type, nullptr};
        tlNext = &(*tlNext)->next;
    }
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
        PeerPoolMgr::Checkpoint(standby.mgr, "tcp_up peer");
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
    PeerPoolMgr::Stop(standby.mgr);
    fwdPconnPool->closeAllTo(this);
    // TODO: After eventDelete() becomes safe, cancel netdbExchangeStart event
    // to prevent accumulation of those events for frequently removed peers.
}

/// reports peer_t using squid.conf syntax for valid values
static
std::ostream &
operator <<(std::ostream &os, const peer_t type)
{
    switch (type) {

    case PEER_PARENT:
        os << "parent";
        break;

    case PEER_SIBLING:
        os << "sibling";
        break;

    case PEER_MULTICAST:
        os << "multicast";
        break;

    default: // includes PEER_NONE
        os << "peer_type=" << type;
        break;
    }

    return os;
}

void
PrintDirectives(std::ostream &os, const CachePeer &peer)
{
    os << "cache_peer " << peer.host << ' ' << neighborTypeStr(&peer) << ' ' << peer.http_port << ' ' << peer.icp.port;
    PrintOptions(os, peer);
    os << "\n";

    if (peer.access) {
        // XXX: This code adds a single space indentation for the second
        // cache_peer_access rule and beyond because AsList() does not handle
        // multiline output specially when honoring delimitedBy().
        const auto prefix = ToSBuf("cache_peer_access ", peer.name);
        os << AsList(ToTree(peer.access).treeDump(prefix, &Acl::AllowOrDeny)).delimitedBy(" ");
    }

    for (auto t = peer.typelist; t; t = t->next) {
        os << "neighbor_type_domain " << peer.name << ' ' << t->type << ' ' << t->domain;
    }
}

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.name;
}

