/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer source hash based selection */

#ifndef SQUID_PEER_SOURCEHASH_H_
#define SQUID_PEER_SOURCEHASH_H_

class CachePeer;
class HttpRequest;
class ps_state;

void peerSourceHashInit(void);
CachePeer * peerSourceHashSelectParent(HttpRequest * request, ps_state *);

#endif /* SQUID_PEER_SOURCEHASH_H_ */

