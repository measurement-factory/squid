/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "CachePeer.h"
#include "defines.h"
#include "neighbors.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "PeerDigest.h"
#include "PeerPoolMgr.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "util.h"

CBDATA_CLASS_INIT(CachePeer);

CachePeer::CachePeer(const char * const hostname):
    name(xstrdup(hostname)),
    host(xstrdup(hostname)),
    probeCodeContext(new DetailedCodeContext("cache_peer probe", ToSBuf("current cache_peer probe: ", *this)))
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
    void *digestTmp = nullptr;
    if (cbdataReferenceValidDone(digest, &digestTmp))
        peerDigestNotePeerGone(static_cast<PeerDigest *>(digestTmp));
    xfree(digest_url);
#endif

    delete next;

    xfree(login);

    delete standby.pool;

    // the mgr job will notice that its owner is gone and stop
    PeerPoolMgr::Checkpoint(standby.mgr, "peer gone");

    xfree(domain);
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

void
CachePeer::noteFailure()
{
    stats.last_connect_failure = squid_curtime;
    if (tcp_up > 0)
        --tcp_up;

    if (consideredAliveByAdmin()) {
        if (!tcp_up) {
            debugs(15, DBG_IMPORTANT, "Detected DEAD " << neighborTypeStr(this) << ": " << name);
            stats.logged_state = PEER_DEAD;
        } else {
            debugs(15, 2, "additional failures needed to mark cache_peer " << *this << " DEAD: " << tcp_up);
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
CountOutgoingConnectionSuccess(const Comm::ConnectionPointer &conn)
{
    if (conn) {
        if (const auto peer = conn->getPeer())
            peer->noteSuccess();
    }
}

static bool
OutgoingConnectionFailureIsImportant(const Comm::ConnectionPointer &conn)
{
    if (const auto peer = conn ? conn->getPeer() : nullptr)
        return peer->consideredAliveByAdmin();

    // a DIRECT connection or a connection to a DEAD cache_peer
    return false;
}

OutgoingConnectionFailure::OutgoingConnectionFailure(const Comm::ConnectionPointer &conn):
    important(OutgoingConnectionFailureIsImportant(conn)),
    conn_(conn)
{
}

OutgoingConnectionFailure::~OutgoingConnectionFailure()
{
    if (important && conn_) {
        debugs(15, DBG_IMPORTANT, "ERROR: Squid BUG: Missing OutgoingConnectionFailure::countAfterReport() call");
        countAfterReport(); // work around the problem
    }
}

void
OutgoingConnectionFailure::countAfterReport() const
{
    if (important && conn_) {
        if (const auto peer = conn_->getPeer())
            peer->noteFailure();
    }
    conn_ = nullptr; // signal destructor that countAfterReport() has been called
}

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.name;
}

