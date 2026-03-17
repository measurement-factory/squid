/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CACHEPEERS_H
#define SQUID_SRC_CACHEPEERS_H

#include "base/forward.h"
#include "CachePeer.h"
#include "mem/PoolingAllocator.h"
#include "peering.h"

#include <memory>
#include <vector>

/// configured cache_peers
using KeptCachePeers = std::vector<KeptCachePeer, PoolingAllocator<KeptCachePeer> >;

/// manages active/current set of configured cache_peers
class CachePeers final
{
public:
    ~CachePeers();

    /// owns stored CachePeer objects
    using Storage = KeptCachePeers;

    // XXX: document
    void reset(Configuration::SmoothReconfiguration &);

    /// stores a configured cache_peer
    /// \sa remove()
    void add(const KeptCachePeer &);

    /// forgets the given peer
    /// \prec the given peer was previously add()ed
    /// \returns a never-nil pointer to the removed peer
    KeptCachePeer remove(CachePeer *);

    /// the number of currently stored (i.e. added and not removed) cache_peers
    auto size() const { return storage.size(); }

    /// currently stored (i.e. added and not removed) cache_peers
    auto &raw() const { return storage; }

    /* peer iterators forming a sequence for C++ range-based for loop API */
    using const_iterator = Storage::const_iterator;
    auto begin() const { return storage.cbegin(); }
    auto end() const { return storage.cend(); }

    /// A CachePeer to query next when scanning all peer caches in hope to fetch
    /// a remote cache hit. \sa neighborsUdpPing()
    /// \param iteration a 0-based index of a loop scanning all peers
    CachePeer &nextPeerToPing(size_t iteration);

private:
    void reAdd(const KeptCachePeer &);

    /// cache_peers in configuration/parsing order
    Storage storage;

    /// total number of completed peer scans by nextPeerToPing()-calling code
    uint64_t peerPolls_ = 0;
};

/// All configured cache_peers that are still available/relevant.
/// \returns an empty container if no cache_peers were configured or all
/// configured cache_peers were removed (e.g., by DeleteConfigured()).
const CachePeers &CurrentCachePeers();

/// Adds a given configured peer to CurrentCachePeers() collection.
/// \prec findCachePeerByName() is false for the given peer
/// \sa DeleteConfigured()
void AddConfigured(const KeptCachePeer &);

/// Destroys the given peer after removing it from the set of configured peers.
/// \prec findCachePeerByName() is true for the given peer
/// \sa AddConfigured()
void DeleteConfigured(CachePeer *);

/// A subset of CurrentCachePeers() suitable for long-term storage.
/// Users must specify the selection algorithm and the order of entries.
/// DeleteConfigured() must keep every stored copy in sync.
using SelectedCachePeers = CachePeers::Storage;

/// Template parameter type for Configuration::Component specialization that
/// handles smooth cache_peer_access reconfiguration
class CachePeerAccesses {};

/// configured cache_peer with a given name (or nil)
CachePeer *findCachePeerByName(const char *);
/// cache_peer with a given name among the given peers (or nil)
CachePeer *findCachePeerByNameIn(const KeptCachePeers &, const char *name);

/// XXX
class BeingConfiguredCachePeers
{
public:
    /// successfully parsed cache_peer directives; future CurrentCachePeers().storage
    KeptCachePeers parsed;
};

#endif /* SQUID_SRC_CACHEPEERS_H */

