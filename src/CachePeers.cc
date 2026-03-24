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
#include "neighbors.h"
#include "peer_sourcehash.h"
#include "peer_userhash.h"
#include "PeerPoolMgr.h"
#include "PeerSelectState.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "tools.h"

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
    // keep in sync with reAdd()
    Assure(peer);
    storage.push_back(peer);
    Assure(!peer->index);
    peer->index = size();
    PeerPoolMgr::StartManagingIfNeeded(*peer);
}

/// reset() helper for old unchanged cache_peers that need to be re-indexed
/// \returns whether the given peer has changed its position
bool
CachePeers::reAdd(const KeptCachePeer &peer)
{
    // keep in sync with add()
    Assure(peer);
    const auto oldIndex = peer->index;
    storage.push_back(peer);
    const auto newIndex = size(); // often the same as oldIndex
    debugs(15, 2, "old " << *peer << " was at " << oldIndex << " now at " << newIndex);
    Assure(oldIndex);
    peer->index = newIndex;
    return oldIndex != newIndex;
}

KeptCachePeer
CachePeers::remove(CachePeer * const peer)
{
    const auto pos = std::find_if(storage.begin(), storage.end(), [&](const auto &storePeer) {
        return storePeer.getRaw() == peer;
    });
    Assure(pos != storage.end());
    const auto removedPeer = *pos;
    storage.erase(pos);
    removedPeer->noteRemoval();
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
DeleteConfigured(CachePeer * const peer)
{
    Assure(Config.peers);
    const auto removedPeer = Config.peers->remove(peer);
    peerSelectDrop(*removedPeer);
}

bool
IsConflicting(const AnyP::PortCfg &portCfg, const CachePeer &peer)
{
    const auto me = getMyHostname();
    return strcasecmp(peer.host, me) == 0 && peer.http_port == portCfg.s.port();
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
findCachePeerByNameIn(const KeptCachePeers &peers, const char *name)
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
    //
    // Completion of this TODO should resurrect PeerPoolMgr::SyncConfig() or similar calls.

    // Workspace to find and eventually remove cache_peers that changed or were
    // not mentioned in the fresh configuration at all. This container does not
    // have cache_peers with unchanged configuration -- we want to _move_ (i.e.
    // reindex) rather than remove() those, so that they keep their connections.
    SelectedCachePeers peersToRemove;

    debugs(15, 5, storage.size() << " old and " << sr.fresh.cachePeers->parsed.size() << " new cache_peers");

    const auto oldStorage = std::move(storage);
    storage.clear(); // get `storage` back into known state

    auto sawChanges = false; // including added, removed, and moved cache_peers

    // helps compare CachePeer configurations
    const auto toDirectives = [](const auto &peer) {
        SBufStream os;
        PrintDirectives(os, peer);
        return os.buf();
    };

    for (const auto &fresh: sr.fresh.cachePeers->parsed) {
        if (const auto old = findCachePeerByNameIn(oldStorage, fresh->name)) {
            Assure(fresh != old); // different pointers
            if (toDirectives(*old) == toDirectives(*fresh)) { // same configuration
                const auto changedPosition = reAdd(old);
                sawChanges = sawChanges || changedPosition;
            } else {
                debugs(15, DBG_IMPORTANT, "Reconfigured existing cache_peer: " << *fresh);
                add(fresh);
                peersToRemove.push_back(old);
                sawChanges = true;
            }
        } else {
            debugs(15, DBG_IMPORTANT, "Adding new cache_peer: " << *fresh);
            add(fresh);
            sawChanges = true;
        }
    }

    for (const auto &old: oldStorage) {
        if (!findCachePeerByNameIn(sr.fresh.cachePeers->parsed, old->name)) {
            debugs(15, DBG_IMPORTANT, "Removing old cache_peer: " << *old);
            peersToRemove.push_back(old);
            sawChanges = true;
        }
        // else case was handled in the previous loop
    }

    Assure(peersToRemove.size() <= oldStorage.size());
    Assure(storage.size() == sr.fresh.cachePeers->parsed.size());

    for (const auto &p: peersToRemove)
        p->noteRemoval();

    if (!sawChanges) {
        debugs(15, 2, "no changes detected");
        return;
    }

    carpInit();
    peerSourceHashInit();
#if USE_AUTH
    peerUserHashInit();
#endif

    neighbors_init(true);
}

