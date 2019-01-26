/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 15    Neighbor Routines */

#ifndef SQUID_NEIGHBORS_H_
#define SQUID_NEIGHBORS_H_

#include "anyp/forward.h"
#include "enums.h"
#include "ICP.h"
#include "lookup_t.h"
#include "typedefs.h" //for IRCB

#include <vector>

class HttpRequest;
class HttpRequestMethod;
class CachePeer;
class PeerSelector;
class StoreEntry;
class URL;

CachePeer *getFirstPeer(void);

/// Appends to PeerSelector peers list the first up parent group.
/// This is includes all existing peers in the order they are configured.
void retrieveFirstUpParentsGroup(PeerSelector *);

CachePeer *getNextPeer(CachePeer *);

/// Retrieves a list of neighbors which can be pinged for the
/// given HttpRequest object
void getNeighborsToPing(PeerSelector *, std::vector<CbcPointer<CachePeer> > &);

/// Iterates over the given neighbors list and ping them
/// \param peers The neighbors list
/// \param req The request initiated the peer selection procedure
/// \param entry The StoreEntry built for the given HttpRequest object or nil
/// \param callback A callback to use to report ping results (HIT, MISS, etc)
/// \param ps The PeerSelector to call back.
/// \param exprep The ping replies to expect
/// \param timeout A timeout for ping procedure. It depends on pinged neighbors configuration
int neighborsUdpPing(std::vector<CbcPointer<CachePeer> > &peers, HttpRequest *req, StoreEntry *entry, IRCB *callback, PeerSelector *ps, int *exprep, int *timeout);

void neighborAddAcl(const char *, const char *);

void neighborsUdpAck(const cache_key *, icp_common_t *, const Ip::Address &);
void neighborAdd(const char *, const char *, int, int, int, int, int);
void neighbors_init(void);
#if USE_HTCP
void neighborsHtcpClear(StoreEntry *, const char *, HttpRequest *, const HttpRequestMethod &, htcp_clr_reason);
#endif
CachePeer *peerFindByName(const char *);
CachePeer *peerFindByNameAndPort(const char *, unsigned short);

/// Appends to PeerSelector peers list the default parents group.
/// This is includes all existing peers configured as 'default' in the
/// order they are configured.
void retrieveDefaultParentsGroup(PeerSelector *);

/// Appends to PeerSelector peers list the round-robin ordered parents group.
/// This is includes the peers configured with round-robin option.
void retrieveRoundRobinParentsGroup(PeerSelector *);

/// Appends to PeerSelector peers list the weighted round-robin ordered parents
/// group.
/// This is includes the peers configured with weighted-round-robin option.
void retrieveWeightedRoundRobinParentsGroup(PeerSelector *);

/// Updates the CachePeer after selected for use with the round-robin method.
void updateRoundRobinParent(CachePeer *);

/// Updates the CachePeer after selected for use with the weighted-round-robin
/// method.
void updateWeightedRoundRobinParent(CachePeer *, HttpRequest *);

void peerClearRRStart(void);
void peerClearRR(void);
lookup_t peerDigestLookup(CachePeer * p, PeerSelector *);

/// Appends to PeerSelector peers list the cache digest based best parents
/// group (the CD_PARENT_HIT group).
void neighborsDigestSelect(PeerSelector *);

void peerNoteDigestLookup(HttpRequest * request, CachePeer * p, lookup_t lookup);
void peerNoteDigestGone(CachePeer * p);
int neighborUp(const CachePeer * e);
const char *neighborTypeStr(const CachePeer * e);
peer_t neighborType(const CachePeer *, const AnyP::Uri &);
void peerConnectFailed(CachePeer *);
void peerConnectSucceded(CachePeer *);
void dump_peer_options(StoreEntry *, CachePeer *);
int peerHTTPOkay(const CachePeer *, PeerSelector *);

// TODO: Consider moving this method to CachePeer class.
/// \returns the effective connect timeout for the given peer
time_t peerConnectTimeout(const CachePeer *peer);

/// \returns max(1, timeout)
time_t positiveTimeout(const time_t timeout);

/// Whether we can open new connections to the peer (e.g., despite max-conn)
bool peerCanOpenMore(const CachePeer *p);
/// Whether the peer has idle or standby connections that can be used now
bool peerHasConnAvailable(const CachePeer *p);
/// Notifies peer of an associated connection closure.
void peerConnClosed(CachePeer *p);

CachePeer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */

