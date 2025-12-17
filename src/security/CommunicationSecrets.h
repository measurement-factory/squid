/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_COMMUNICATION_SECRETS_H
#define SQUID_SRC_SECURITY_COMMUNICATION_SECRETS_H

#include "sbuf/SBuf.h"
#include "security/forward.h"

#include <iosfwd>

namespace Security {

/// Manages TLS key material related to Client Hello and Server Hello messages:
/// session ID, (pre)master key, and client random.
class HandshakeSecrets
{
public:
    /// no secrets
    HandshakeSecrets() = default;

    /// imports currently available secrets from the given TLS connection
    explicit HandshakeSecrets(const Connection &);

    /// whether we know all record()-worthy secrets
    bool gotAll() const;

    /// extracts given connection secrets and updates stored ones as needed
    /// \returns whether any secrets stored got updated
    bool learnNew(const Connection &);

    /// logs all known secrets using a (multiline) SSLKEYLOGFILE format
    void record(std::ostream &) const;

public:
    /// do not record() known CLIENT_RANDOM
    bool suppressClientRandomReporting = false;

private:
#if USE_OPENSSL
    void getClientRandom(const Connection &sconn);
    void getSessionId(const Session &session);
    void getMasterKey(const Session &session);
#else
    // Secret extraction is not supported in builds using other TLS libraries.
    // Secret extraction is impractical in builds without TLS libraries.
#endif

    SBuf id; ///< TLS session ID
    SBuf random; ///< CLIENT_RANDOM from the TLS connection
    SBuf key; ///< TLS session (pre-)master key
};

/// Manages TLS key material suitable for (later) decryption of TLS exchanges:
/// early secrets, handshake secrets, client random, updated keys, etc.
class CommunicationSecrets
{
public:
    /// no secrets
    CommunicationSecrets() = default;

    /// updates stored secrets as needed
    /// \returns secrets to report in NSS SSLKEYLOGFILE line(s) format
    SBuf exportFormatted(const Connection &);

    /// copies given TLS secrets in NSS SSLKEYLOGFILE line(s) format
    void importFormatted(const char *);

private:
    HandshakeSecrets handshakeSecrets;

    /// Accumulates unrecorded key material in NSS SSLKEYLOGFILE format.
    /// Uses new line to separate secrets.
    /// \sa KeyLogger::noteKeyMaterial()
    SBuf libraryProvidedSecrets;
};

} // namespace Security

/// prints secrets in NSS SSLKEYLOGFILE line(s) format
std::ostream &operator <<(std::ostream &, const Security::HandshakeSecrets &);

#endif /* SQUID_SRC_SECURITY_COMMUNICATION_SECRETS_H */

