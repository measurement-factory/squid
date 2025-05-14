/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer user hash based selection */

#ifndef SQUID_SRC_PEER_USERHASH_H
#define SQUID_SRC_PEER_USERHASH_H

#include "configuration/forward.h"

class CachePeer;
class PeerSelector;

CachePeer * peerUserHashSelectParent(PeerSelector *);

/// Schedules an update of global UserHash peer selection tables (if not already scheduled).
void peerUserHashReset(Configuration::SmoothReconfiguration &);

/// Calls peerUserHashReset() if UserHash-related configuration of the given
/// `current` peer is changing.
///
/// \param current reflects an existing CachePeer state; this CachePeer may not
/// be a UserHash cache_peer
///
/// \param fresh is a new configuration for the current peer; it may not be a
/// UserHash cache_peer configuration
void peerUserHashResetIfChanged(Configuration::SmoothReconfiguration &, const CachePeer &current, const CachePeer &fresh);

#endif /* SQUID_SRC_PEER_USERHASH_H */

