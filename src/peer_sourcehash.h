/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Peer source hash based selection */

#ifndef SQUID_PEER_SOURCEHASH_H_
#define SQUID_PEER_SOURCEHASH_H_

class PeerSelector;

void peerSourceHashInit(void);
void peerSourceHashSelectParent(PeerSelector *);

#endif /* SQUID_PEER_SOURCEHASH_H_ */

