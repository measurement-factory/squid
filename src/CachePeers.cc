/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "CachePeers.h"
#include "ConfigOption.h"
#include "configuration/Smooth.h"
#include "neighbors.h"
#include "PeerPoolMgr.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"

#include <algorithm>

/* CachePeers */

CachePeers::~CachePeers()
{
    while (!storage.empty())
        remove(storage.front().getRaw());
}

CachePeer &
CachePeers::nextPeerToPing(const size_t pollIndex)
{
    Assure(size());

    // Remember the number of polls to keep shifting each poll starting point,
    // to avoid always polling the same group of peers before other peers and
    // risk overloading that first group with requests.
    if (!pollIndex)
        ++peerPolls_;

    // subtract 1 to set the very first pos to zero
    const auto pos = (peerPolls_ - 1 + pollIndex) % size();

    return *storage[pos];
}

void
CachePeers::absorb(const KeptCachePeer &peer)
{
    storage.push_back(peer);
    storage.back()->index = size();
}

void
CachePeers::remove(CachePeer * const peer)
{
    const auto pos = std::find_if(storage.begin(), storage.end(), [&](const auto &storePeer) {
        return storePeer.getRaw() == peer;
    });
    Assure(pos != storage.end());
    PeerPoolMgr::Stop(peer->standby.mgr);
    storage.erase(pos);
}

const CachePeers &
CurrentCachePeers()
{
    if (Config.peers)
        return *Config.peers;

    static const CachePeers empty;
    return empty;
}

void
AbsorbConfigured(const KeptCachePeer &peer)
{
    if (!Config.peers)
        Config.peers = new CachePeers;

    Config.peers->absorb(peer);

    peerClearRRStart();
}

void
DeleteConfigured(CachePeer * const peer)
{
    Assure(Config.peers);
    Config.peers->remove(peer);
}

/* Configuration::Component<CachePeerAccesses> */

template <>
void
Configuration::Component<CachePeerAccesses>::StartSmoothReconfiguration(SmoothReconfiguration &)
{
    // our needs are handled by Component<CachePeers*>::StartSmoothReconfiguration()
}

template <>
void
Configuration::Component<CachePeerAccesses>::FinishSmoothReconfiguration(SmoothReconfiguration &)
{
    // our needs are handled by Component<CachePeers*>::FinishSmoothReconfiguration()
}

/* Configuration::Component<CachePeers*> */

template <>
void
Configuration::Component<CachePeers*>::StartSmoothReconfiguration(SmoothReconfiguration &)
{
    // Mark old cache_peers as stale so that FinishSmoothReconfiguration() can
    // find old peers that are no longer present in the new configuration file.
    //
    // XXX: Marking old cache_peers is not good enough because we do not want to
    // remember to check the `stale` flag whenever (re)configuration code
    // accesses a CachePeer object (e.g., see a check in parse_peer_access()).
    // TODO: Stash old cache_peers here and forget them upon successful smooth
    // reconfiguration but bring them back on smooth reconfiguration failures.
    // To handle smooth reconfiguration failures, add
    // Configuration::Component<T>::AbortSmoothReconfiguration()?
    for (const auto &p: CurrentCachePeers()) {
        p->stale = true;
        aclDestroyAccessList(&p->access); // XXX: This will go away when stale peers are stashed (see XXX above).
    }
}

template <>
void
Configuration::Component<CachePeers*>::FinishSmoothReconfiguration(SmoothReconfiguration &sr)
{
    // disable cache_peers that were not mentioned in the fresh configuration
    RawCachePeers peersToRemove;

    for (const auto &p: CurrentCachePeers()) {
        if (p->stale)
            peersToRemove.push_back(p.getRaw());
    }

    while (peersToRemove.size()) {
        const auto p = peersToRemove.back();
        peersToRemove.pop_back();
        debugs(15, DBG_IMPORTANT, "WARNING: Removing old cache_peer not present in new configuration: " << *p);
        peerSelectDrop(sr, *p);
        Assure(!p->access); // parse_peer_access() rejects cache_peer_access directives naming stale peers
        DeleteConfigured(p);
    }
}

