/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer source hash based selection */

#ifndef SQUID_SRC_PEER_SOURCEHASH_H
#define SQUID_SRC_PEER_SOURCEHASH_H

#include "configuration/forward.h"

class CachePeer;
class PeerSelector;

CachePeer * peerSourceHashSelectParent(PeerSelector*);

/// Schedules an update of global SourceHash peer selection tables (if not already scheduled).
void peerSourceHashReset(Configuration::SmoothReconfiguration &);

/// Calls peerSourceHashReset() if SourceHash-related configuration of the given
/// `current` peer is changing.
///
/// \param current reflects an existing CachePeer state; this CachePeer may not
/// be a SourceHash cache_peer
///
/// \param fresh is a new configuration for the current peer; it may not be a
/// SourceHash cache_peer configuration
void peerSourceHashResetIfChanged(Configuration::SmoothReconfiguration &, const CachePeer &current, const CachePeer &fresh);

#endif /* SQUID_SRC_PEER_SOURCEHASH_H */

