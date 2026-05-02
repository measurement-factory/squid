/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
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
    Assure(peer);
    storage.push_back(peer);
    Assure(!peer->index);
    peer->index = size();
    PeerPoolMgr::StartManagingIfNeeded(*peer);
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
    debugs(15, 5, storage.size() << " old and " << sr.fresh.cachePeers->parsed.size() << " new cache_peers");

    const auto oldStorage = std::move(storage);
    storage.clear(); // get `storage` back into known state

    for (const auto &old: oldStorage) {
        if (!findCachePeerByNameIn(sr.fresh.cachePeers->parsed, old->name)) {
            debugs(15, DBG_IMPORTANT, "Removing old cache_peer: " << *old);
        }
        // else case is handled in the loop below

        old->noteRemoval();
    }

    // helps compare CachePeer configurations
    const auto toDirectives = [](const auto &peer) {
        SBufStream os;
        PrintDirectives(os, peer);
        return os.buf();
    };

    for (const auto &fresh: sr.fresh.cachePeers->parsed) {
        if (const auto old = findCachePeerByNameIn(oldStorage, fresh->name)) {
            Assure(fresh != old); // different pointers

            // Do not report alive cache_peers explicitly because that state is
            // normal/expected and, hence, not interesting. There is also no
            // consistent terminology for describing that state: mgr:server_list
            // and some code use "Up", but a lot of code uses "Alive" as well.
            const auto status = !fresh->tcp_up ? "DEAD " : "";

            const auto sameSpelling = (toDirectives(*old) == toDirectives(*fresh));
            debugs(15, DBG_IMPORTANT, "Reconfiguring existing " << status <<
                   "cache_peer (with " <<
                   (sameSpelling ? "unchanged" : "changed") <<
                   " configuration spelling): " << *fresh);
            add(fresh);
        } else {
            debugs(15, DBG_IMPORTANT, "Adding new cache_peer: " << *fresh);
            add(fresh);
        }
    }

    Assure(storage.size() == sr.fresh.cachePeers->parsed.size());

    carpInit();
    peerSourceHashInit();
#if USE_AUTH
    peerUserHashInit();
#endif

    neighbors_init(); // XXX: Check for port conflict earlier to avoid exceptions

    // peerClearRR() is unnecessary because all CurrentCachePeers() have the same initial rr_count
}

