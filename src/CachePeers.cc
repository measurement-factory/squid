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
#include "ConfigOption.h"
#include "configuration/Smooth.h"
#include "FwdState.h"
#include "neighbors.h"
#include "pconn.h"
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

void
CachePeers::remove(CachePeer * const peer)
{
    const auto pos = std::find_if(storage.begin(), storage.end(), [&](const auto &storePeer) {
        return storePeer.getRaw() == peer;
    });
    Assure(pos != storage.end());
    PeerPoolMgr::Stop(peer->standby.mgr);
    fwdPconnPool->closeAllTo(peer);
    storage.erase(pos);
}

KeptCachePeer
CachePeers::take(const char * const name)
{
    const auto it = std::remove_if(storage.begin(), storage.end(), [&](const auto &storePeer) {
        return !strcasecmp(name, storePeer->name);
    });
    if (it != storage.end()) {
        const auto peer = *it;
        storage.erase(it);
        return peer;
    }
    return nullptr;
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
Configuration::Component<CachePeers*>::StartSmoothReconfiguration(SmoothReconfiguration &sr)
{
    // TODO: Bring the old cache_peers back on smooth reconfiguration failures.
    // To handle smooth reconfiguration failures, add
    // Configuration::Component<T>::AbortSmoothReconfiguration()
    sr.oldPeers = Config.peers;
    Config.peers = nullptr;
}

template <>
void
Configuration::Component<CachePeers*>::FinishSmoothReconfiguration(SmoothReconfiguration &sr)
{
    if (!sr.oldPeers)
        return;

    for (const auto &p: *sr.oldPeers) {
        debugs(15, DBG_IMPORTANT, "WARNING: Removing old cache_peer not present in new configuration: " << *p);
        peerSelectDrop(sr, *p);
    }

    delete sr.oldPeers;
    sr.oldPeers = nullptr;
}

