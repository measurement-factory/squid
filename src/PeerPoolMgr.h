/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PEERPOOLMGR_H
#define SQUID_SRC_PEERPOOLMGR_H

#include "base/AsyncJob.h"
#include "base/forward.h"
#include "base/JobWait.h"
#include "comm/forward.h"
#include "security/forward.h"

class HttpRequest;
class CachePeer;
class CommConnectCbParams;

/// Maintains an fixed-size "standby" PconnPool for a single CachePeer.
class PeerPoolMgr: public AsyncJob
{
    CBDATA_CHILD(PeerPoolMgr);

public:
    typedef CbcPointer<PeerPoolMgr> Pointer;

    /// Creates and starts peer.standby.mgr job if it does not exist and
    /// peer.standby.limit configuration requires one. Does nothing otherwise.
    static void StartManagingIfNeeded(CachePeer &);

    /// Brings an existing mgr job (if any) in sync with its peer and pool
    /// state. May end mgr job. Unlike StartManagingIfNeeded(), does not create
    /// new mgr jobs.
    static void Checkpoint(const Pointer &mgr, const char *reason);

    /// Brings peer->standby.mgr in sync with peer->standby.limit configuration,
    /// calling either StartManagingIfNeeded() or Checkpoint().
    static void SyncConfig(CachePeer &);

    /// terminates the existing mgr job (if any)
    static void Stop(const Pointer &mgr);

    explicit PeerPoolMgr(CachePeer *aPeer);
    ~PeerPoolMgr() override;

    PrecomputedCodeContextPointer codeContext;

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
};

#endif /* SQUID_SRC_PEERPOOLMGR_H */

