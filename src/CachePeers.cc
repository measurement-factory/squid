/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "CachePeers.h"
#include "carp.h"
#include "ConfigOption.h"
#include "configuration/Smooth.h"
#include "FwdState.h"
#include "neighbors.h"
#include "pconn.h"
#include "peer_sourcehash.h"
#include "peer_userhash.h"
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
CachePeers::add(const KeptCachePeer &peer)
{
    storage.push_back(peer);
    storage.back()->index = size();
}

KeptCachePeer
CachePeers::remove(CachePeer * const peer)
{
    const auto pos = std::find_if(storage.begin(), storage.end(), [&](const auto &storePeer) {
        return storePeer.getRaw() == peer;
    });
    Assure(pos != storage.end());
    const auto removedPeer = *pos;
    PeerPoolMgr::Stop(peer->standby.mgr);
    peer->noteRemoval();
    fwdPconnPool->closeAllTo(peer);
    storage.erase(pos);
    return removedPeer;
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
AddConfigured(const KeptCachePeer &peer)
{
    if (!Config.peers)
        Config.peers = new CachePeers;

    Config.peers->add(peer);

    peerClearRRStart();
}

void
DeleteConfigured(Configuration::SmoothReconfiguration &sr, CachePeer * const peer)
{
    Assure(Config.peers);
    const auto removedPeer = Config.peers->remove(peer);
    peerSelectDrop(sr, *removedPeer);
}

void
DeleteConfigured(CachePeer * const peer)
{
    Assure(Config.peers);
    const auto removedPeer = Config.peers->remove(peer);
    peerSelectDrop(*removedPeer);
}

CachePeer *
findCachePeerByName(const char * const name)
{
    for (const auto &p: CurrentCachePeers()) {
        if (!strcasecmp(name, p->name))
            return p.getRaw();
    }
    return nullptr;
}

CachePeer *
findCachePeerByNameIn(KeptCachePeers &peers, const char *name)
{
    // XXX: Do not duplicate findCachePeerByName()
    for (const auto &p: peers) {
        if (strcasecmp(name, p->name) == 0)
            return p.getRaw();
    }
    return nullptr;
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
        p->stale = true; // XXX: Remove this field
        aclDestroyAccessList(&p->access); // XXX: This will go away when stale peers are stashed (see XXX above).
    }
}

template <>
void
Configuration::Component<CachePeers*>::FinishSmoothReconfiguration(SmoothReconfiguration &sr)
{
    if (!Config.peers && !sr.fresh.cachePeers->parsed.size())
        return;

    // TODO: Avoid duplicating this code.
    if (!Config.peers)
        Config.peers = new CachePeers;

    Config.peers->reset(sr);
}

void
CachePeers::reset(Configuration::SmoothReconfiguration &sr)
{
    // TODO: Do not remove() and then add() completely unchanged peers. Doing so
    // results in closing (and opening) various idle connections, which can be
    // harmful. Detect changes in all cache_peer-based directives, including
    // cache_peer_access and neighbor_type_domain! Order changes are probably OK
    // as long as we reindex (at the end of this method).

    // workspace to find and remove cache_peers that changed or were not
    // mentioned in the fresh configuration at all
    SelectedCachePeers peersToRemove;

    debugs(15, 5, storage.size() << " old and " << sr.fresh.cachePeers->parsed.size() << " new cache_peers");

    for (const auto &p: sr.fresh.cachePeers->parsed) {
        if (!findCachePeerByNameIn(storage, p->name))
            debugs(15, DBG_IMPORTANT, "Adding new cache_peer: " << *p);
    }

    for (const auto &p: storage) {
        if (const auto stayed = findCachePeerByNameIn(sr.fresh.cachePeers->parsed, p->name)) {
            Assure(p != stayed); // for now, see above TODO about not removing-then-adding peers
            debugs(15, DBG_IMPORTANT, "Reconfigured cache_peer: " << *p);
        } else {
            debugs(15, DBG_IMPORTANT, "WARNING: Removing old cache_peer not present in new configuration: " << *p);
        }
        peersToRemove.push_back(p);
    }

    for (const auto &p: peersToRemove) {
        // XXX: stop deleting p->access earlier!
        Assure(!p->access); // parse_peer_access() rejects cache_peer_access directives naming stale peers
        remove(p.getRaw());
    }

    Assure(storage.empty()); // for now, see above TODO about not removing-then-adding peers
    for (const auto &p: sr.fresh.cachePeers->parsed) {
        add(p);
    }

    carpInit();
    peerSourceHashInit();
#if USE_AUTH
    peerUserHashInit();
#endif

    neighbors_init(); // XXX: Check for port conflict earlier to avoid exceptions
}

