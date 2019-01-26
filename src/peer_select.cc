/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 44    Peer Selection Algorithm */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncCbdataCalls.h"
#include "base/InstanceId.h"
#include "CachePeer.h"
#include "carp.h"
#include "client_side.h"
#include "dns/LookupDetails.h"
#include "errorpage.h"
#include "event.h"
#include "FwdState.h"
#include "globals.h"
#include "hier_code.h"
#include "htcp.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ICP.h"
#include "ip/tools.h"
#include "ipcache.h"
#include "neighbors.h"
#include "peer_sourcehash.h"
#include "peer_userhash.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"

/**
 * A CachePeer which has been selected as a possible destination.
 * Listed as pointers here so as to prevent duplicates being added but will
 * be converted to a set of IP address path options before handing back out
 * to the caller.
 *
 * Certain connection flags and outgoing settings will also be looked up and
 * set based on the received request and CachePeer settings before handing back.
 */
class FwdServer
{
    MEMPROXY_CLASS(FwdServer);

public:
    FwdServer(CachePeer *p, hier_code c, int gid) :
        _peer(p),
        code(c),
        groupId(gid),
        next(nullptr)
    {}

    /// whether the given peer is already covered by this selection
    bool duplicates(CachePeer *peer, const hier_code code, const int groupId);

    CbcPointer<CachePeer> _peer;                /* NULL --> origin server */
    hier_code code;

    /// Selection groupId for peer.
    /// Peers selected with the same method (eg netdb, roundrobin etc)
    /// has the same groupId. Currently as groupId values the related
    /// hier_code is used.
    int groupId;
    FwdServer *next;
};

static struct {
    int timeouts;
} PeerStats;

static const char *DirectStr[] = {
    "DIRECT_UNKNOWN",
    "DIRECT_NO",
    "DIRECT_MAYBE",
    "DIRECT_YES"
};

/// a helper class to report a selected destination (for debugging)
class PeerSelectionDumper
{
public:
    PeerSelectionDumper(const PeerSelector * const aSelector, const CachePeer * const aPeer, const hier_code aCode, int aGroupId):
        selector(aSelector), peer(aPeer), code(aCode), groupId(aGroupId) {}

    const PeerSelector * const selector; ///< selection parameters
    const CachePeer * const peer; ///< successful selection info
    const hier_code code; ///< selection algorithm
    const int groupId; ///< selection groupId for peer.
};

CBDATA_CLASS_INIT(PeerSelector);

/// prints PeerSelectionDumper (for debugging)
static std::ostream &
operator <<(std::ostream &os, const PeerSelectionDumper &fsd)
{
    os << hier_code_str[fsd.code] << '/' << fsd.groupId;

    if (fsd.peer)
        os << '/' << fsd.peer->host;
    else if (fsd.selector) // useful for DIRECT and gone PINNED destinations
        os << '#' << fsd.selector->request->url.host();

    return os;
}

bool
FwdServer::duplicates(CachePeer *peer, const hier_code peerCode, const int peerGroup)
{
    // there can be at most one PINNED destination
    if (peerCode == PINNED)
        return code == PINNED;

    // there can be at most one CachePeer within peer's group
    if (groupId)
        return groupId == peerGroup && _peer == peer;

    // non-grouped destinations are uniquely identified by their CachePeer pointers
    // (even though a DIRECT destination might match a cache_peer network address)
    return _peer == peer;
}

PeerSelector::~PeerSelector()
{
    while (servers) {
        FwdServer *next = servers->next;
        delete servers;
        servers = next;
    }

    if (entry) {
        debugs(44, 3, entry->url());

        if (entry->ping_status == PING_WAITING)
            eventDelete(HandlePingTimeout, this);

        entry->ping_status = PING_DONE;
    }

    if (acl_checklist) {
        debugs(44, DBG_IMPORTANT, "BUG: peer selector gone while waiting for a slow ACL");
        delete acl_checklist;
    }

    if (entry) {
        entry->unlock("peerSelect");
        entry = NULL;
    }
}

bool
PeerSelector::findIcpNeighborsToPing()
{
    assert(entry);
    assert(direct != DIRECT_YES);

    if (entry->ping_status != PING_NONE)
        return false;

    debugs(44, 3, entry->url());

    if (!request->flags.hierarchical && direct != DIRECT_NO)
        return false;

    if (EBIT_TEST(entry->flags, KEY_PRIVATE) && !neighbors_do_private_keys)
        if (direct != DIRECT_NO)
            return false;

    getNeighborsToPing(this, candidatePingPeers);

    debugs(44, 3, "counted " << candidatePingPeers.size() << "candidate neighbors");

    return (candidatePingPeers.size() > 0);
}

PeerSelectionInitiator::PeerSelectionInitiator(HttpRequest *req):
    request(req)
{}

PeerSelectionInitiator::~PeerSelectionInitiator()
{
    delete lastError;
    delete selector;
}

void
PeerSelectionInitiator::notePeer(CachePeer *peer, const hier_code code)
{
    if (peer == nullptr && code == HIER_NONE) {
        PeerSelectionInitiator::subscribed = false;
        if (lastError && foundPaths) {
            // nobody cares about errors if we found destinations despite them
            debugs(44, 3, "forgetting the last error");
            delete lastError;
            lastError = nullptr;
        }
        // May kill our self:
        noteDestinationsEnd(lastError);
        return;
    }

    peer_ = peer;
    peerType_ = code;
    if (code == ORIGINAL_DST) {
        assert(peer_ == nullptr);
        if (request->clientConnectionManager.valid()) {
            const Ip::Address originalDst = request->clientConnectionManager->clientConnection->local;
            noteIp(originalDst);
            return;
        }
        requestMoreDestinations(); //nothing to send continue to the next Peer
        return;
    }

    if (code == PINNED) {
        const Ip::Address tmpnoaddr;
        noteIp(tmpnoaddr);
        return;
    }

    const char *host = peer_.valid() ? peer_->host : request->url.host();
    debugs(44, 2, "Find IP destination for: " << request->url << "' via " << host);
    Dns::nbgethostbyname(host, this);
}

bool
PeerSelectionInitiator::wantsMoreDestinations() const
{
    const auto maxCount = Config.forward_max_tries;
    return maxCount >= 0 && foundPaths <
           static_cast<std::make_unsigned<decltype(maxCount)>::type>(maxCount);
}


void
PeerSelectionInitiator::noteIp(const Ip::Address &ip)
{
    if (peer_.raw() && !peer_.valid()) //Peer gone, abort?
        return;

    // for TPROXY spoofing, we must skip unusable addresses
    if (request->flags.spoofClientIp && !(peer_.valid() && peer_->options.no_tproxy) ) {
        if (ip.isIPv4() != request->client_addr.isIPv4())
            return; // cannot spoof the client address on this link
    }

    Comm::ConnectionPointer path = new Comm::Connection();
    path->remote = ip;
    path->peerType = peerType_;
    if (peerType_ != PINNED && peerType_ != ORIGINAL_DST) {
        if (peer_.valid()) {
            path->remote.port(peer_.valid() ? peer_->http_port : request->url.port());
            path->setPeer(peer_.get());
        } else
            path->remote.port(request->url.port());
    }

    // if not pinned check for a configured outgoing address
    if (peerType_ != PINNED)
        getOutgoingAddress(request.getRaw(), path);

    ++foundPaths;
    noteDestination(path);
}

void
PeerSelectionInitiator::noteIps(const Dns::CachedIps *ips, const Dns::LookupDetails &details)
{
    if (ips)
        return; // noteIp() calls have already processed all IPs

    debugs(17, 3, "Unknown host: " << (peer_.valid() ? peer_->host : request->url.host()));
    if (peerType_ == HIER_DIRECT) {
        assert(!peer_.raw());
        // discard any previous error.
        delete lastError;
        lastError = new ErrorState(ERR_DNS_FAIL, Http::scServiceUnavailable, request.getRaw());
        lastError->dnsError = details.error;
        requestMoreDestinations(); //nothing to send continue to the next Peer
    }
}

void
PeerSelectionInitiator::noteLookup(const Dns::LookupDetails &details)
{
    request->recordLookup(details);
}

void
PeerSelectionInitiator::startSelectingDestinations(const AccessLogEntry::Pointer &ale, StoreEntry *entry)
{
    subscribed = true;

    if (entry)
        debugs(44, 3, *entry << ' ' << entry->url());
    else
        debugs(44, 3, request->method);

    assert(!selector);
    selector = new PeerSelector(request.getRaw(), entry);
    selector->al = ale;

#if USE_CACHE_DIGESTS
    request->hier.peer_select_start = current_time;
#endif

    requestMoreDestinations();
    // and wait for noteDestination() and/or noteDestinationsEnd() calls
}

void
PeerSelectionInitiator::requestMoreDestinations()
{
    if (subscribed && wantsMoreDestinations() && selector) {
        typedef PeerSelector::CbDialer Dialer;
        AsyncCall::Pointer call = asyncCall(44, 5, "PeerSelectionInitiator::notePeer",
                                            Dialer(this, &PeerSelectionInitiator::notePeer));

        selector->requestPeer(call);
        return;
    }
    notePeer(nullptr, HIER_NONE);
}

void
PeerSelector::checkNeverDirectDone(const allow_t answer)
{
    acl_checklist = nullptr;
    debugs(44, 3, answer);
    never_direct = answer;
    switch (answer) {
    case ACCESS_ALLOWED:
        /** if never_direct says YES, do that. */
        direct = DIRECT_NO;
        debugs(44, 3, "direct = " << DirectStr[direct] << " (never_direct allow)");
        planNextStep(DoPinned, "check for pinned after NeverDirect");
        break;
    case ACCESS_DENIED: // not relevant.
    case ACCESS_DUNNO:  // not relevant.
        break;
    case ACCESS_AUTH_REQUIRED:
        debugs(44, DBG_IMPORTANT, "WARNING: never_direct resulted in " << answer << ". Username ACLs are not reliable here.");
        break;
    }
    selectMore();
}

void
PeerSelector::CheckNeverDirectDone(allow_t answer, void *data)
{
    static_cast<PeerSelector*>(data)->checkNeverDirectDone(answer);
}

void
PeerSelector::checkAlwaysDirectDone(const allow_t answer)
{
    acl_checklist = nullptr;
    debugs(44, 3, answer);
    always_direct = answer;
    switch (answer) {
    case ACCESS_ALLOWED:
        /** if always_direct says YES, do that. */
        direct = DIRECT_YES;
        debugs(44, 3, "direct = " << DirectStr[direct] << " (always_direct allow)");
        planNextStep(DoPinned, "check for pinned after AlwaysDirect");
        break;
    case ACCESS_DENIED: // not relevant.
    case ACCESS_DUNNO:  // not relevant.
        break;
    case ACCESS_AUTH_REQUIRED:
        debugs(44, DBG_IMPORTANT, "WARNING: always_direct resulted in " << answer << ". Username ACLs are not reliable here.");
        break;
    }

    selectMore();
}

void
PeerSelector::CheckAlwaysDirectDone(allow_t answer, void *data)
{
    static_cast<PeerSelector*>(data)->checkAlwaysDirectDone(answer);
}

/// \returns true (after destroying "this") if the peer initiator is gone
/// \returns false (without side effects) otherwise
bool
PeerSelector::selectionAborted()
{
    if (callback_ && !callback_->canceled())
        return false;

    debugs(44, 3, "Aborting peer selection: Initiator gone or lost interest.");
    return true;
}

bool
PeerSelector::accessCheckCached(const CachePeer *p, allow_t &answer) const
{
    if (!p)
        return false;

    for (auto it : aclPeersCache) {
        if (p == it.first.valid()) {
            answer = it.second;
            return true;
        }
    }
    return false;
}

static void
checkLastPeerAccessWrapper(allow_t answer, void *data)
{
    auto selector = static_cast<PeerSelector *>(data);
    selector->checkLastPeerAccess(answer);
}

void
PeerSelector::checkLastPeerAccess(const allow_t answer)
{
    acl_checklist = nullptr;

    if (selectionAborted())
        return;

    assert(currentServer);
    if (currentServer->_peer.valid())
        aclPeersCache.push_back(std::pair<CbcPointer<CachePeer>, allow_t>(currentServer->_peer, answer));

    if (!answer.allowed() || !currentServer->_peer.valid()) {
        currentServer = currentServer->next;
        selectMore();
        return;
    }

    if (currentServer->groupId)
        groupSelect(currentServer);

    updateSelectedPeer(currentServer->_peer.get(), currentServer->code);

    callback(currentServer->_peer.get(), currentServer->code);
    currentServer = currentServer->next;
}

void
PeerSelector::updateSelectedPeer(CachePeer *p, hier_code code)
{
#if USE_CACHE_DIGESTS
    if (code == CD_PARENT_HIT || code == CD_SIBLING_HIT) {
        peerNoteDigestLookup(request.getRaw(), p, LOOKUP_HIT);
        // If none selected and digestLookup not updates the default values
        // in request->hier should be enough.

        // Do not ping for peers if any of the above peer types succeed
        disablePinging = true;
    } else
#endif
    if (code == CLOSEST_PARENT)
        disablePinging = true;
    else if (code == WEIGHTED_ROUNDROBIN_PARENT && p->options.weighted_roundrobin)
        updateWeightedRoundRobinParent(p, request.getRaw());
    else if (code == ROUNDROBIN_PARENT && p->options.roundrobin)
        updateRoundRobinParent(p);
}

void
PeerSelector::sendNextPeer()
{
    if (selectionAborted())
        return;

    if (!currentServer) {
        // Done with peers
        ping.stop = current_time;
        request->hier.ping = ping; // final result
        callback(nullptr, HIER_NONE);
        return;
    }

    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we must use only the original client destination when going DIRECT
    // on intercepted traffic which failed Host verification
    const bool isIntercepted = !request->flags.redirected &&
        (request->flags.intercepted || request->flags.interceptTproxy);
    const bool useOriginalDst = Config.onoff.client_dst_passthru || !request->flags.hostVerified;
    const bool choseDirect = currentServer->code == HIER_DIRECT;
    if (isIntercepted && useOriginalDst && choseDirect) {
        callback(nullptr, ORIGINAL_DST);

        currentServer = currentServer->next;
        return;
    }

    if (!currentServer->_peer.raw()) { // eg PINNED
        callback(nullptr, currentServer->code);
        currentServer = currentServer->next;
        return;
    }

    checkPeerAccess(currentServer->_peer.get(), checkLastPeerAccessWrapper);
}

void
PeerSelector::checkPeerAccess(CachePeer *p, ACLCB *cb)
{
    if (p->access) {
        allow_t cached;
        if (accessCheckCached(p, cached))
            cb(cached, this);
        else {
            ACLFilledChecklist *ch = new ACLFilledChecklist(p->access, request.getRaw(), nullptr);
            ch->al = al;
            acl_checklist = ch;
            acl_checklist->syncAle(request.getRaw(), nullptr);
            // TODO: Avoid deep recursion when finding the first allowed peer
            // using fast/cached ACLs.
            acl_checklist->nonBlockingCheck(cb, this);
        }
    } else
        cb(ACCESS_ALLOWED, this);
}

int
PeerSelector::checkNetdbDirect()
{
#if USE_ICMP
    CachePeer *p;
    int myrtt;
    int myhops;

    if (direct == DIRECT_NO)
        return 0;

    /* base lookup on RTT and Hops if ICMP NetDB is enabled. */

    myrtt = netdbHostRtt(request->url.host());
    debugs(44, 3, "MY RTT = " << myrtt << " msec");
    debugs(44, 3, "minimum_direct_rtt = " << Config.minDirectRtt << " msec");

    if (myrtt && myrtt <= Config.minDirectRtt)
        return 1;

    myhops = netdbHostHops(request->url.host());

    debugs(44, 3, "MY hops = " << myhops);
    debugs(44, 3, "minimum_direct_hops = " << Config.minDirectHops);

    if (myhops && myhops <= Config.minDirectHops)
        return 1;

    p = whichPeer(closest_parent_miss);

    if (p == NULL)
        return 0;

    debugs(44, 3, "closest_parent_miss RTT = " << ping.p_rtt << " msec");

    if (myrtt && myrtt <= ping.p_rtt)
        return 1;

#endif /* USE_ICMP */

    return 0;
}

void
PeerSelector::planNextStep(SelectionState state, const char *comment)
{
    selectionState = state;
    debugs(44, 4, "New selection state: " << state << " reason: " << comment);

    switch(state) {
    case DoFinalizePing:
        assert(entry);
        entry->ping_status = PING_WAITING;
        break;
    case DoFinal:
        if (entry)
            entry->ping_status = PING_DONE;
        break;
    default:
        // nothing to do
        break;
    }
}

void
PeerSelector::selectMore()
{
    if (selectionAborted())
        return;

    debugs(44, 3, request->method << ' ' << request->url.host());

    while (!currentServer && selectionState != DoFinished) {
        switch (selectionState) {
        case DoCheckDirect:
            checkDirect();
            if (selectionState == DoCheckDirect)
                return; // wait nonblocking acls to finish
            break;
        case DoPinned:
            assert(!entry || entry->ping_status == PING_NONE);
            selectPinned();
            break;
        case DoSelectSomeNeighbors:
            assert(entry);
            selectSomeNeighbor();
            break;
        case DoStartPing:
            assert(entry);
            startIcpPing();
            break;
        case DoContinuePing:
            continueIcpPing();
            if (selectionState == DoContinuePing)
                return; // wait for pinging results
            break;
        case DoFinalizePing:
            finalizeIcpPing();
            break;
        case DoFinal:
            finalSelections();
            break;
        default:
            assert(selectionState == DoFinished);
            break;
        }
    }

    // Start acl-check and resolve currentServer or finish
    sendNextPeer();
    return;
}

void
PeerSelector::requestPeer(AsyncCall::Pointer &call)
{
    assert(!callback_);
    callback_ = call;
    selectMore();
}

void
PeerSelector::checkDirect()
{
    if (direct == DIRECT_UNKNOWN) {
        if (always_direct == ACCESS_DUNNO) {
            debugs(44, 3, "direct = " << DirectStr[direct] << " (always_direct to be checked)");
            /** check always_direct; */
            ACLFilledChecklist *ch = new ACLFilledChecklist(Config.accessList.AlwaysDirect, request.getRaw(), nullptr);
            ch->al = al;
            acl_checklist = ch;
            acl_checklist->syncAle(request.getRaw(), nullptr);
            acl_checklist->nonBlockingCheck(CheckAlwaysDirectDone, this);
            return;
        } else if (never_direct == ACCESS_DUNNO) {
            debugs(44, 3, "direct = " << DirectStr[direct] << " (never_direct to be checked)");
            /** check never_direct; */
            ACLFilledChecklist *ch = new ACLFilledChecklist(Config.accessList.NeverDirect, request.getRaw(), nullptr);
            ch->al = al;
            acl_checklist = ch;
            acl_checklist->syncAle(request.getRaw(), nullptr);
            acl_checklist->nonBlockingCheck(CheckNeverDirectDone, this);
            return;
        } else if (request->flags.noDirect) {
            /** if we are accelerating, direct is not an option. */
            direct = DIRECT_NO;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (forced non-direct)");
        } else if (request->flags.loopDetected) {
            /** if we are in a forwarding-loop, direct is not an option. */
            direct = DIRECT_YES;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (forwarding loop detected)");
        } else if (checkNetdbDirect()) {
            direct = DIRECT_YES;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (checkNetdbDirect)");
        } else {
            direct = DIRECT_MAYBE;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (default)");
        }

        debugs(44, 3, "direct = " << DirectStr[direct]);
    }

    planNextStep(DoPinned, "check for pinned");
}

void
PeerSelector::finalSelections()
{
    switch (direct) {

    case DIRECT_YES:
        selectSomeDirect();
        break;

    case DIRECT_NO:
        selectSomeParent();
        selectAllParents();
        break;

    default:

        if (Config.onoff.prefer_direct)
            selectSomeDirect();

        if (request->flags.hierarchical || !Config.onoff.nonhierarchical_direct) {
            selectSomeParent();
            selectAllParents();
        }

        if (!Config.onoff.prefer_direct)
            selectSomeDirect();

        break;
    }
    planNextStep(DoFinished, "peer selection done");
}

bool peerAllowedToUse(const CachePeer *, PeerSelector*);

/// Selects a pinned connection if it exists, is valid, and is allowed.
void
PeerSelector::selectPinned()
{
    if (request->pinnedConnection()) {
        CachePeer *pear = request->pinnedConnection()->pinnedPeer();
        if (Comm::IsConnOpen(request->pinnedConnection()->validatePinnedConnection(request.getRaw(), pear))) {
            const bool usePinned = pear ? peerAllowedToUse(pear, this) : (direct != DIRECT_NO);
            if (usePinned) {
                addSelection(pear, PINNED);
                planNextStep(DoFinal, "pinned connection");
                return;
            }
        }
    }

    // If the pinned connection is prohibited (for this request) or gone, then
    // the initiator must decide whether it is OK to open a new one instead.

    if (!entry)
        planNextStep(DoFinal, "null entry, disable neighbors lookup/ping");
    else if (direct == DIRECT_YES)
        planNextStep(DoFinal, "do direct");
    else
        planNextStep(DoSelectSomeNeighbors, "neighbors lookup");
}

/**
 * Selects a group of neighbors (parent or sibling) based on one of the
 * following methods:
 *      Cache Digests
 *      CARP
 *      ICMP Netdb RTT estimates
 *      ICP/HTCP queries
 */
void
PeerSelector::selectSomeNeighbor()
{
    assert(direct != DIRECT_YES);

#if USE_CACHE_DIGESTS
    neighborsDigestSelect(this);
#endif
    netdbClosestParent(this);

    planNextStep(DoStartPing, "consider pinging");
}

static void
checkNeighborToPingAccessWrapper(allow_t answer, void *data)
{
    auto selector = static_cast<PeerSelector *>(data);
    selector->checkNeighborToPingAccess(answer);
}

void
PeerSelector::checkNeighborToPingAccess(const allow_t answer)
{
    acl_checklist = nullptr;
    assert(!candidatePingPeers.empty());
    CbcPointer<CachePeer> p = candidatePingPeers.front();
    candidatePingPeers.erase(candidatePingPeers.begin());

    if (p.valid()) {
        aclPeersCache.push_back(std::make_pair(p, answer));

        if (answer.allowed()) { // check for the next peer
            debugs(44, 5, "Will ping peer " << p->name);
            peersToPing.push_back(p);
        }
    }

    continueIcpPing();
    if (selectionState == DoFinal) // pinging aborted or finished
        selectMore();
}

bool
PeerSelector::moreNeighborsToPing()
{
    while (!candidatePingPeers.empty() && !candidatePingPeers.front().valid())
        candidatePingPeers.erase(candidatePingPeers.begin());

    if (candidatePingPeers.empty())
        return false;

    CachePeer *p = candidatePingPeers.front().get();

    checkPeerAccess(p, checkNeighborToPingAccessWrapper);

    return true;
}

void
PeerSelector::startIcpPing()
{
    assert(selectionState == DoStartPing);
    if (disablePinging)
        planNextStep(DoFinal, "pinging is disabled");
    else if (!findIcpNeighborsToPing())
        planNextStep(DoFinal, "no neighbors to ping");
    else
        planNextStep(DoContinuePing, "found candidate neighbors to ping");
}

void
PeerSelector::continueIcpPing()
{
    // moreNeighborsToPing will do acl check for the next candidate neighbor
    // and will callback us
    if (!moreNeighborsToPing()) {
        doIcpPing();

        if (ping.n_replies_expected > 0) {
            planNextStep(DoFinalizePing, "waiting neighbors replies");
            // Nothing to do, HandlePingReply will call PeerSelector::selectMore
            // when a HIT or all of the replies are received.
        } else
            planNextStep(DoFinal, "no neighbors replies expected");
    }
}

void
PeerSelector::finalizeIcpPing()
{
    assert(selectionState == DoFinalizePing);
    assert(entry && entry->ping_status == PING_WAITING);
    selectSomeNeighborReplies();
    planNextStep(DoFinal, "ping done");
}

void
PeerSelector::doIcpPing()
{
    if (peersToPing.empty()) {
        debugs(44, 3, "No servers to ping");
        return;
    }

    debugs(44, 3, "Start pinging " << peersToPing.size() << " servers");

    ping.start = current_time;
    ping.n_sent = neighborsUdpPing(
        peersToPing,
        request.getRaw(),
        entry,
        HandlePingReply,
        this,
        &ping.n_replies_expected,
        &ping.timeout);

    if (ping.n_sent == 0)
        debugs(44, DBG_CRITICAL, "WARNING: neighborsUdpPing returned 0");

    debugs(44, 3, ping.n_replies_expected <<
           " ICP replies expected, RTT " << ping.timeout <<
           " msec");

    if (ping.n_replies_expected > 0) {
        eventAdd("PeerSelector::HandlePingTimeout",
                 HandlePingTimeout,
                 this,
                 0.001 * ping.timeout,
                 0);
    }
}

/// Selects a neighbor (parent or sibling) based on ICP/HTCP replies.
void
PeerSelector::selectSomeNeighborReplies()
{
    CachePeer *p = NULL;
    hier_code code = HIER_NONE;
    assert(entry->ping_status == PING_WAITING);
    assert(direct != DIRECT_YES);

    if (checkNetdbDirect()) {
        code = CLOSEST_DIRECT;
        addSelection(nullptr, code);
        return;
    }

    if ((p = hit)) {
        code = hit_type == PEER_PARENT ? PARENT_HIT : SIBLING_HIT;
    } else {
        if (!closest_parent_miss.isAnyAddr()) {
            p = whichPeer(closest_parent_miss);
            code = CLOSEST_PARENT_MISS;
        } else if (!first_parent_miss.isAnyAddr()) {
            p = whichPeer(first_parent_miss);
            code = FIRST_PARENT_MISS;
        }
    }
    if (p && code != HIER_NONE) {
        addSelection(p, code);
    }
}

/// Adds a "direct" entry if the request can be forwarded to the origin server.
void
PeerSelector::selectSomeDirect()
{
    if (direct == DIRECT_NO)
        return;

    /* WAIS is not implemented natively */
    if (request->url.getScheme() == AnyP::PROTO_WAIS)
        return;

    addSelection(nullptr, HIER_DIRECT);
}

void
PeerSelector::selectSomeParent()
{
    debugs(44, 3, request->method << ' ' << request->url.host());

    if (direct == DIRECT_YES)
        return;

    peerSourceHashSelectParent(this);
#if USE_AUTH
    peerUserHashSelectParent(this);
#endif
    carpSelectParent(this);

    retrieveRoundRobinParentsGroup(this);

    retrieveWeightedRoundRobinParentsGroup(this);

    retrieveFirstUpParentsGroup(this);

    retrieveDefaultParentsGroup(this);
}

/// Adds alive parents. Used as a last resort for never_direct.
void
PeerSelector::selectAllParents()
{
    CachePeer *p;
    /* Add all alive parents */

    for (p = Config.peers; p; p = p->next) {
        /* XXX: neighbors.c lacks a public interface for enumerating
         * parents to a request so we have to dig some here..
         */

        if (neighborType(p, request->url) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, this))
            continue;

        addSelection(p, ANY_OLD_PARENT);
    }

    /* XXX: should add dead parents here, but it is currently
     * not possible to find out which parents are dead or which
     * simply are not configured to handle the request.
     */
    /* Add default parent as a last resort */
    retrieveDefaultParentsGroup(this);
}

void
PeerSelector::handlePingTimeout()
{
    debugs(44, 3, url());

    planNextStep(DoFinal, "ping timed out");

    if (selectionAborted())
        return;

    ++PeerStats.timeouts;
    ping.timedout = 1;
    selectMore();
}

void
PeerSelector::HandlePingTimeout(void *data)
{
    static_cast<PeerSelector*>(data)->handlePingTimeout();
}

void
peerSelectInit(void)
{
    memset(&PeerStats, '\0', sizeof(PeerStats));
}

void
PeerSelector::handleIcpParentMiss(CachePeer *p, icp_common_t *header)
{
    int rtt;

#if USE_ICMP
    if (Config.onoff.query_icmp) {
        if (header->flags & ICP_FLAG_SRC_RTT) {
            rtt = header->pad & 0xFFFF;
            int hops = (header->pad >> 16) & 0xFFFF;

            if (rtt > 0 && rtt < 0xFFFF)
                netdbUpdatePeer(request->url, p, rtt, hops);

            if (rtt && (ping.p_rtt == 0 || rtt < ping.p_rtt)) {
                closest_parent_miss = p->in_addr;
                ping.p_rtt = rtt;
            }
        }
    }
#endif /* USE_ICMP */

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (!closest_parent_miss.isAnyAddr())
        return;

    rtt = (tvSubMsec(ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (first_parent_miss.isAnyAddr() || rtt < ping.w_rtt) {
        first_parent_miss = p->in_addr;
        ping.w_rtt = rtt;
    }
}

void
PeerSelector::handleIcpReply(CachePeer *p, const peer_t type, icp_common_t *header)
{
    icp_opcode op = header->getOpCode();
    debugs(44, 3, icp_opcode_str[op] << ' ' << url());
#if USE_CACHE_DIGESTS && 0
    /* do cd lookup to count false misses */

    if (p && request)
        peerNoteDigestLookup(request, p,
                             peerDigestLookup(p, this));

#endif

    ++ping.n_recv;

    if (op == ICP_MISS || op == ICP_DECHO) {
        if (type == PEER_PARENT)
            handleIcpParentMiss(p, header);
    } else if (op == ICP_HIT) {
        hit = p;
        hit_type = type;
        selectMore();
        return;
    }

    if (ping.n_recv < ping.n_replies_expected)
        return;

    selectMore();
}

#if USE_HTCP
void
PeerSelector::handleHtcpReply(CachePeer *p, const peer_t type, HtcpReplyData *htcp)
{
    debugs(44, 3, (htcp->hit ? "HIT" : "MISS") << ' ' << url());
    ++ping.n_recv;

    if (htcp->hit) {
        hit = p;
        hit_type = type;
        selectMore();
        return;
    }

    if (type == PEER_PARENT)
        handleHtcpParentMiss(p, htcp);

    if (ping.n_recv < ping.n_replies_expected)
        return;

    selectMore();
}

void
PeerSelector::handleHtcpParentMiss(CachePeer *p, HtcpReplyData *htcp)
{
    int rtt;

#if USE_ICMP
    if (Config.onoff.query_icmp) {
        if (htcp->cto.rtt > 0) {
            rtt = (int) htcp->cto.rtt * 1000;
            int hops = (int) htcp->cto.hops * 1000;
            netdbUpdatePeer(request->url, p, rtt, hops);

            if (rtt && (ping.p_rtt == 0 || rtt < ping.p_rtt)) {
                closest_parent_miss = p->in_addr;
                ping.p_rtt = rtt;
            }
        }
    }
#endif /* USE_ICMP */

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (!closest_parent_miss.isAnyAddr())
        return;

    rtt = (tvSubMsec(ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (first_parent_miss.isAnyAddr() || rtt < ping.w_rtt) {
        first_parent_miss = p->in_addr;
        ping.w_rtt = rtt;
    }
}

#endif

void
PeerSelector::HandlePingReply(CachePeer * p, peer_t type, AnyP::ProtocolType proto, void *pingdata, void *data)
{
    if (proto == AnyP::PROTO_ICP)
        static_cast<PeerSelector*>(data)->handleIcpReply(p, type, static_cast<icp_common_t*>(pingdata));

#if USE_HTCP

    else if (proto == AnyP::PROTO_HTCP)
        static_cast<PeerSelector*>(data)->handleHtcpReply(p, type, static_cast<HtcpReplyData*>(pingdata));

#endif

    else
        debugs(44, DBG_IMPORTANT, "ERROR: ignoring an ICP reply with unknown protocol " << proto);
}

void
PeerSelector::addSelection(CachePeer *peer, const hier_code code, const int groupId)
{
    // Find the end of the servers list. Bail on a duplicate destination.
    auto **serversTail = &servers;
    while (const auto server = *serversTail) {
        if (server->duplicates(peer, code, groupId)) {
            debugs(44, 3, "skipping " << PeerSelectionDumper(this, peer, code, groupId) <<
                   "; have " << PeerSelectionDumper(this, server->_peer.get(), server->code, server->groupId));
            return;
        }
        serversTail = &server->next;
    }

    debugs(44, 3, "adding " << PeerSelectionDumper(this, peer, code, groupId));
    *serversTail = new FwdServer(peer, code, groupId);

    if (!currentServer)
        currentServer = *serversTail;
}

void
PeerSelector::groupSelect(FwdServer *fs)
{
    const int gid = fs->groupId;
    CbcPointer<CachePeer> p = fs->_peer;
    fs->groupId = 0;
    FwdServer **srv = &fs->next;
    // Remove any other FwdServer has the same gid or pointes to the same peer
    while (*srv) {
        if ((*srv)->groupId == gid || (*srv)->_peer == p) {
            auto *tmp = (*srv);
            *srv = tmp->next;
            delete tmp;
        } else
            srv = &(*srv)->next;
    }
}

PeerSelector::PeerSelector(HttpRequest *req, StoreEntry *anEntry):
    request(req),
    entry (anEntry),
    always_direct(Config.accessList.AlwaysDirect?ACCESS_DUNNO:ACCESS_DENIED),
    never_direct(Config.accessList.NeverDirect?ACCESS_DUNNO:ACCESS_DENIED),
    direct(DIRECT_UNKNOWN),
    servers (NULL),
    first_parent_miss(),
    closest_parent_miss(),
    hit(NULL),
    hit_type(PEER_NONE),
    acl_checklist (nullptr)
{
    if (entry)
        entry->lock("PeerSelector");
}

const SBuf
PeerSelector::url() const
{
    if (entry)
        return SBuf(entry->url());

    if (request)
        return request->effectiveRequestUri();

    static const SBuf noUrl("[no URL]");
    return noUrl;
}

void
PeerSelector::callback(CachePeer *peer, const hier_code code)
{
    request->hier.ping = ping;

    if (code == HIER_NONE)
        debugs(44, 2, id << " found all " << foundPeers << " peers for " << url());
    else
        debugs(44, 2, id << " found peer " << (peer ? peer->name : "direct") << ", " << foundPeers << " peer for " << url());
    debugs(44, 2, "  always_direct = " << always_direct);
    debugs(44, 2, "   never_direct = " << never_direct);
    debugs(44, 2, "       timedout = " << ping.timedout);

    assert(callback_);
    CbDialer *dialer = dynamic_cast<CbDialer*>(callback_->getDialer());
    dialer->peer_ = peer;
    dialer->code_ = code;
    ScheduleCallHere(callback_);
    callback_ = nullptr;
    if (code != HIER_NONE)
        ++foundPeers;
}

InstanceIdDefinitions(PeerSelector, "PeerSelector");

ping_data::ping_data() :
    n_sent(0),
    n_recv(0),
    n_replies_expected(0),
    timeout(0),
    timedout(0),
    w_rtt(0),
    p_rtt(0)
{
    start.tv_sec = 0;
    start.tv_usec = 0;
    stop.tv_sec = 0;
    stop.tv_usec = 0;
}

