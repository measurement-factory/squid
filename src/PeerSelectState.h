/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   SQUID_PEERSELECTSTATE_H
#define   SQUID_PEERSELECTSTATE_H

#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#include "base/CbcPointer.h"
#include "base/RefCount.h"
#include "comm/forward.h"
#include "hier_code.h"
#include "http/forward.h"
#include "ip/Address.h"
#include "ipcache.h"
#include "mem/forward.h"
#include "PingData.h"

#include <vector>

class ErrorState;
class HtcpReplyData;
class icp_common_t;
class PeerSelector;
class StoreEntry;

void peerSelectInit(void);

/// Interface for those who need a list of destination paths to forward a
/// request to.
class PeerSelectionInitiator: public Dns::IpReceiver
{
public:
    explicit PeerSelectionInitiator(HttpRequest *req);
    virtual ~PeerSelectionInitiator();

    /// called when a new unique destination has been found
    virtual void noteDestination(Comm::ConnectionPointer path) = 0;

    /// called when there will be no more noteDestination() calls
    /// \param error is a possible reason why no destinations were found; it is
    /// guaranteed to be nil if there was at least one noteDestination() call
    virtual void noteDestinationsEnd(ErrorState *error) = 0;

    /* Dns::IpReceiver API */
    virtual void noteIp(const Ip::Address &) override;
    virtual void noteIps(const Dns::CachedIps *, const Dns::LookupDetails &) override;
    virtual void noteLookup(const Dns::LookupDetails &) override;

    /* protected: */
    /// Initiates asynchronous peer selection that eventually
    /// results in zero or more noteDestination() calls and
    /// exactly one noteDestinationsEnd() call.
    void startSelectingDestinations(const AccessLogEntry::Pointer &ale, StoreEntry *entry);

    HttpRequestPointer request;

protected:
    /// Request for more destinations. The caller will be informed for any
    /// new destination via noteDestination and noteDestinationsEnd methods
    void requestMoreDestinations();

    /// whether noteDestination() and noteDestinationsEnd() calls are allowed
    bool subscribed = false;

private:

    /// Initiates a DNS lookup for the given peer or finalizes the peer
    // selection if peer is nil.
    void notePeer(CachePeer *peer, const hier_code code);

    /// \returns whether the initiator may use more destinations
    bool wantsMoreDestinations() const;

    /// Used PeerSelector object to retrieve candidate peers
    PeerSelector *selector = nullptr;

    hier_code peerType_ = HIER_NONE; ///< current candidate peers type
    CbcPointer<CachePeer> peer_; ///< current candidate peer or nil for origin server
    size_t foundPaths = 0; ///< number of unique destinations identified so far

    ///< The last DNS error.
    ErrorState *lastError = nullptr;
};

class FwdServer;

/// Finds peer (including origin server) IPs for forwarding a single request.
/// Gives PeerSelectionInitiator each found destination, in the right order.
class PeerSelector
{
    CBDATA_CLASS(PeerSelector);

public:
    /// key/CachePeer pairs list
    template<typename Key> using CachePeersByKey = std::vector<std::pair<Key, CachePeer*> >;

    class CbDialer: public CallDialer {
    public:
        typedef void (PeerSelectionInitiator::*Method)(CachePeer *, hier_code);
        CbDialer(PeerSelectionInitiator *initiator, Method method):
            forwader_(initiator), method_(method) {}
        virtual ~CbDialer() {}

        /* CallDialer API */
        virtual bool canDial(AsyncCall &call) {return forwader_.valid();}
        virtual void dial(AsyncCall &call) {(&(*forwader_)->*method_)(peer_.raw(), code_);};
        virtual void print(std::ostream &os) const {os << "A peer!";};

        CbcPointer<PeerSelectionInitiator> forwader_;
        Method method_;
        CbcPointer<CachePeer> peer_; /* NULL --> origin server */
        hier_code code_ = HIER_NONE;
    };

    enum SelectionState {
        DoCheckDirect, ///< check for direct
        DoPinned, ///< check for pinned
        DoSelectSomeNeighbors, ///< peers digest and closest parents
        DoStartPing, ///< start pinging peers
        DoContinuePing, ///< pinging procedure
        DoFinalizePing, ///< finalize pinging
        DoFinal, ///< all of the remaining valid peers
        DoFinished ///< all steps finished
    } selectionState = DoCheckDirect; ///< Current selection state

    explicit PeerSelector(HttpRequest *, StoreEntry *entry);
    ~PeerSelector();

    // Produce a URL for display identifying the transaction we are
    // trying to locate a peer for.
    const SBuf url() const;

    /// a single selection loop iteration: attempts to add more destinations
    void selectMore();

    /// Used by caller to requests a new peer.
    void requestPeer(AsyncCall::Pointer &call);

    /// Add the peer to the candidate peers list
    void addSelection(CachePeer*, const hier_code, const int groupId = 0);

    /// Add the given group of CachePeers to the candidate peers list
    /// It sorts the list by the key in ascending order before add it
    /// to candidate peers list.
    /// \param hierCodeFunc a function in the form: "
    ///        hier_code (*hierCodeFunc)(CachePeer *)
    ///        It is used to compute the Hier code of the given peer.
    /// \param groupId an id to use for the given CachePeers group
    template <class Key, typename FUNC> void addGroup(CachePeersByKey<Key> &, FUNC hierCodeFunc, const int groupId);

    /// Similar to the above.
    /// \param hier_code The Hier code to use for all of the peers. Also
    ///        use it as groupId for the given CachePeers group.
    template <class Key> void addGroup(CachePeersByKey<Key> &, const hier_code);

    /// ACL check callback, if peer allowed send it to the caller
    void checkLastPeerAccess(const allow_t answer);

    /// This is an ACL check callback.
    /// If pinging the current neighbor is allowed, store it on peersToPing
    /// list and call continueIcpPing to find the next candidate neightbor.
    void checkNeighborToPingAccess(const allow_t answer);

    HttpRequestPointer request;
    AccessLogEntry::Pointer al; ///< info for the future access.log entry
    StoreEntry *entry;

    void *peerCountMcastPeerXXX = nullptr; ///< a hack to help peerCountMcastPeersStart()

    ping_data ping;

protected:
    /// Discard all duplicated and same-group peers from the peer candidate list
    void groupSelect(FwdServer *);

    /// Checks if the CachePeer ACL check exist in cache (aclPeersCache)
    bool accessCheckCached(const CachePeer *p, allow_t &answer) const;

    /// Run slow acl checks for the given peer.
    void checkPeerAccess(CachePeer *, ACLCB *);

    /// Does final peer updates (statistics etc), before send the peer to caller
    void updateSelectedPeer(CachePeer *, hier_code);

    /// Runs candidatePingPeers list for the next valid Peer
    /// and initializes an non-blocking ACL check for this peer.
    /// \return false if no more candidate neighbors to ping true otherwise
    bool moreNeighborsToPing();

    /// Checks if pinging neighbors supported and there are
    /// available candidate peers for pinging.
    /// It stores the candidate peers to candidatePingPeers list.
    /// \return true if pinging supported and there are configured peers to ping
    bool findIcpNeighborsToPing();

    /// Checks whether the DIRECT is permitted.
    /// Stores the result (DIRECT_[YES|NO|MAYBE]) to direct member
    void checkDirect();

    /// The final peers selections, after all of the available selection
    /// mechanisms are done.
    void finalSelections();

    /// Starts the pinging procedure. Checks if there are available peers
    /// for pinging, and if yes stars a non-blocking acl check on candidate
    /// peers.
    void startIcpPing();

    /// Pinging procedure
    void continueIcpPing();

    /// Collects pinging responses and completes CachePeers lists.
    void finalizeIcpPing();

    /// Ping selected peers stored in peersToPing list
    void doIcpPing();

    /// Callback the caller
    void callback(CachePeer *, hier_code);

    bool selectionAborted();

    void handlePingTimeout();
    void handleIcpReply(CachePeer*, const peer_t, icp_common_t *header);
    void handleIcpParentMiss(CachePeer*, icp_common_t*);
#if USE_HTCP
    void handleHtcpParentMiss(CachePeer*, HtcpReplyData*);
    void handleHtcpReply(CachePeer*, const peer_t, HtcpReplyData*);
#endif

    int checkNetdbDirect();
    void checkAlwaysDirectDone(const allow_t answer);
    void checkNeverDirectDone(const allow_t answer);

    void selectSomeNeighbor();
    void selectSomeNeighborReplies();
    void selectSomeDirect();
    void selectSomeParent();
    void selectAllParents();
    void selectPinned();

    /// Initiates the next selection state step
    void planNextStep(SelectionState, const char *comment);

    /// Start sending the next available peer to the caller or inform
    /// him that no more peers are available.
    void sendNextPeer();

    static IRCB HandlePingReply;
    static ACLCB CheckAlwaysDirectDone;
    static ACLCB CheckNeverDirectDone;
    static EVH HandlePingTimeout;

private:
    allow_t always_direct;
    allow_t never_direct;
    int direct;   // TODO: fold always_direct/never_direct/prefer_direct into this now that ACL can do a multi-state result.

    int foundPeers = 0;
    bool disablePinging = false;
    FwdServer *servers; ///< a linked list of (unresolved) selected peers

    /// The member of servers list which is currently processed and checked
    /// before sent to caller
    FwdServer *currentServer = nullptr;

    AsyncCall::Pointer callback_; ///< caller callback

    /// Temporary list with candidate peers to ping. They will be ACL checked
    /// before added to peersToPing list
    std::vector<CbcPointer<CachePeer> > candidatePingPeers;

    /// The list with available peers for pinging
    std::vector<CbcPointer<CachePeer> > peersToPing;

    // The std::vector selected as type of aclPeersCache because:
    //   1) many PeerSelectState objects expected in squid memory
    //   2) looks that std::vector uses less memory than std::map
    //   3) only few ACL checks results expected in this cache so
    //      I hope that the linear search is not huge problem
    // TODO: Decide whether std::vector is the best storage type for this cache.
    /// Cache for peers ACL checks
    std::vector<std::pair<CbcPointer<CachePeer>, allow_t> > aclPeersCache;

    /*
     * Why are these Ip::Address instead of CachePeer *?  Because a
     * CachePeer structure can become invalid during the CachePeer selection
     * phase, specifically after a reconfigure.  Thus we need to lookup
     * the CachePeer * based on the address when we are finally ready to
     * reference the CachePeer structure.
     */

    Ip::Address first_parent_miss;

    Ip::Address closest_parent_miss;
    /*
     * ->hit can be CachePeer* because it should only be
     * accessed during the thread when it is set
     */
    CachePeer *hit;
    peer_t hit_type;
    ACLChecklist *acl_checklist;

    const InstanceId<PeerSelector> id; ///< unique identification in worker log
};

template <class Key, typename FUNC> void
PeerSelector::addGroup(CachePeersByKey<Key> &peers, FUNC getHierCode, const int groupId)
{
    typedef std::pair<Key, CachePeer *> KeyPeerPair;
    std::sort(peers.begin(), peers.end(), [](const KeyPeerPair &a, const KeyPeerPair &b) { return a.first < b.first; });
    for (auto it : peers) {
        const hier_code code = getHierCode(it.second);
        addSelection(it.second, code, groupId);
    }
}

template <class Key> void
PeerSelector::addGroup(CachePeersByKey<Key> &peers, const hier_code code)
{
    addGroup(peers, [code](const CachePeer *) { return code; }, code);
}

#endif /* SQUID_PEERSELECTSTATE_H */

