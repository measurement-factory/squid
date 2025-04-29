/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

#include <memory>
#include <vector>

/// cache_peer configuration storage
class CachePeers final
{
public:
    ~CachePeers();

    /// owns stored CachePeer objects
    using Storage = std::vector< std::unique_ptr<CachePeer>, PoolingAllocator< std::unique_ptr<CachePeer> > >;

    /// stores a configured cache_peer, becoming responsible for its lifetime
    void absorb(std::unique_ptr<CachePeer> &&);

    /// deletes a previously add()ed CachePeer object
    void remove(CachePeer *);

    /// the number of currently stored (i.e. added and not removed) cache_peers
    auto size() const { return storage.size(); }

    /* peer iterators forming a sequence for C++ range-based for loop API */
    using const_iterator = Storage::const_iterator;
    auto begin() const { return storage.cbegin(); }
    auto end() const { return storage.cend(); }

    /// A CachePeer to query next when scanning all peer caches in hope to fetch
    /// a remote cache hit. \sa neighborsUdpPing()
    /// \param iteration a 0-based index of a loop scanning all peers
    CachePeer &nextPeerToPing(size_t iteration);

private:
    void notifyPeerGone(const CachePeer &) const;

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
void AbsorbConfigured(std::unique_ptr<CachePeer> &&);

/// destroys the given peer after removing it from the set of configured peers
void DeleteConfigured(CachePeer *);

/// Weak pointers to zero or more Config.peers.
/// Users must specify the selection algorithm and the order of entries.
using SelectedCachePeers = std::vector< CbcPointer<CachePeer>, PoolingAllocator< CbcPointer<CachePeer> > >;

/// Temporary, local storage of raw pointers to zero or more Config.peers.
using RawCachePeers = std::vector<CachePeer *, PoolingAllocator<CachePeer*> >;

/// Template parameter type for Configuration::Component specialization that
/// handles smooth cache_peer_access reconfiguration
class CachePeerAccesses {};

#endif /* SQUID_SRC_CACHEPEERS_H */

