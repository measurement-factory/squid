/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_BLINDPEERCONNECTOR_H
#define SQUID_SRC_SECURITY_BLINDPEERCONNECTOR_H

#include "http/forward.h"
#include "security/PeerConnector.h"

class ErrorState;

namespace Security
{

/// A PeerConnector for TLS cache_peers and origin servers. No SslBump capabilities.
class BlindPeerConnector: public Security::PeerConnector {
    CBDATA_CHILD(BlindPeerConnector);
public:
    BlindPeerConnector(HttpRequestPointer &aRequest,
                       const Comm::ConnectionPointer &aServerConn,
                       const AsyncCallback<EncryptorAnswer> &aCallback,
                       const AccessLogEntryPointer &alp,
                       time_t timeout = 0);

    /* Security::PeerConnector API */

    /// Calls parent initialize(), configures the created TLS session object
    /// to try and reuse a TLS session and sets the hostname to use for
    /// certificate validation
    /// \returns true on successful initialization
    bool initialize(Security::SessionPointer &) override;

    FuturePeerContext *peerContext() const override;

    /// On success, stores the used TLS session for later use.
    /// On error, informs the peer.
    void noteNegotiationDone(ErrorState *) override;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_BLINDPEERCONNECTOR_H */

