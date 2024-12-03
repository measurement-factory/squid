/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PEERPOOLMGR_H
#define SQUID_PEERPOOLMGR_H

#include "base/AsyncJob.h"
#include "base/JobWait.h"
#include "comm/forward.h"
#include "security/forward.h"

class HttpRequest;
class CachePeer;
class CommConnectCbParams;

/// CodeContext for cache_peer related classes
class DetailedCodeContext : public CodeContext
{
public:
    typedef RefCount<DetailedCodeContext> Pointer;

    DetailedCodeContext(const char *gist, const SBuf &detail) : gist_(gist),
        detail_(detail)
        {}

    /* CodeContext API */
    ScopedId codeContextGist() const override;
    std::ostream &detailCodeContext(std::ostream &os) const override;

    void setMasterXaction(const MasterXaction::Pointer &mx) { masterXaction = mx; }

private:
    const char *gist_; ///< the id used in codeContextGist()
    const SBuf detail_; ///< the detail used in detailCodeContext()
    /// the corresponding master transaction, if any
    MasterXaction::Pointer masterXaction;
};

/// Maintains an fixed-size "standby" PconnPool for a single CachePeer.
class PeerPoolMgr: public AsyncJob
{
    CBDATA_CHILD(PeerPoolMgr);

public:
    typedef CbcPointer<PeerPoolMgr> Pointer;

    // syncs mgr state whenever connection-related peer or pool state changes
    static void Checkpoint(const Pointer &mgr, const char *reason);

    explicit PeerPoolMgr(CachePeer *aPeer);
    ~PeerPoolMgr() override;

protected:
    /* AsyncJob API */
    void start() override;
    void swanSong() override;
    bool doneAll() const override;

    /// whether the peer is still out there and in a valid state we can safely use
    bool validPeer() const;

    /// Starts new connection, or closes the excess connections
    /// according pool configuration
    void checkpoint(const char *reason);
    /// starts the process of opening a new standby connection (if possible)
    void openNewConnection();
    /// closes 'howMany' standby connections
    void closeOldConnections(const int howMany);

    /// Comm::ConnOpener calls this when done opening a connection for us
    void handleOpenedConnection(const CommConnectCbParams &params);

    /// Security::PeerConnector callback
    void handleSecuredPeer(Security::EncryptorAnswer &answer);

    /// the final step in connection opening (and, optionally, securing) sequence
    void pushNewConnection(const Comm::ConnectionPointer &conn);

private:
    CachePeer *peer; ///< the owner of the pool we manage
    RefCount<HttpRequest> request; ///< fake HTTP request for conn opening code

    /// waits for a transport connection to the peer to be established/opened
    JobWait<Comm::ConnOpener> transportWait;

    /// waits for the established transport connection to be secured/encrypted
    JobWait<Security::BlindPeerConnector> encryptionWait;

    unsigned int addrUsed; ///< counter for cycling through peer addresses

public:
    DetailedCodeContext::Pointer context;
};

#endif /* SQUID_PEERPOOLMGR_H */

