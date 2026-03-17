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

class CachePeer;
class PeerSelector;

CachePeer * peerUserHashSelectParent(PeerSelector *);

/// updates global UserHash peer selection tables
void peerUserHashInit();

#endif /* SQUID_SRC_PEER_USERHASH_H */

