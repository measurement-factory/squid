/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "base/IoManip.h"
#include "sbuf/Stream.h"
#include "security/CommunicationSecrets.h"
#include "security/Session.h"

#include <ostream>

// TODO: Remove Security::HandshakeSecrets after discontinuing support for
// OpenSSL v1.1.0: OpenSSL v1.1.1 provides SSL_CTX_set_keylog_callback() API.

/* Security::HandshakeSecrets */

Security::HandshakeSecrets::HandshakeSecrets(const Connection &sconn)
{
#if USE_OPENSSL
    getClientRandom(sconn);

    if (const auto session = SSL_get_session(&sconn)) {
        getMasterKey(*session);
        getSessionId(*session);
    }
#else
    // Secret extraction is not supported in builds using other TLS libraries.
    // Secret extraction is impractical in builds without TLS libraries.
    (void)sconn;
#endif
}

bool
Security::HandshakeSecrets::gotAll() const
{
    return !id.isEmpty() && (suppressClientRandomReporting || !random.isEmpty()) && !key.isEmpty();
}

bool
Security::HandshakeSecrets::learnNew(const Connection &sconn)
{
    const HandshakeSecrets news(sconn);

    auto sawChange = false;

    if (id != news.id && !news.id.isEmpty()) {
        id = news.id;
        sawChange = true;
    }

    if (!suppressClientRandomReporting && random != news.random && !news.random.isEmpty()) {
        random = news.random;
        sawChange = true;
    }

    if (key != news.key && !news.key.isEmpty()) {
        key = news.key;
        sawChange = true;
    }

    return sawChange;
}

/// writes the given secret (in hex) or, if there is no secret, a placeholder
static void
PrintSecret(std::ostream &os, const SBuf &secret)
{
    if (!secret.isEmpty())
        PrintHex(os, secret.rawContent(), secret.length());
    else
        os << '-';
}

void
Security::HandshakeSecrets::record(std::ostream &os) const {
    // Print SSLKEYLOGFILE blobs that contain at least one known secret.
    // See Wireshark tls_keylog_process_lines() source code for format details.

    // Each line printed below has format that includes two secrets, but one of
    // those secrets may be discovered later. SSLKEYLOGFILE consumers like
    // Wireshark discard lines with just one secret, so we print both secrets
    // when both become known, even if we have already printed one of them.

    // RSA Session-ID:... Master-Key:...
    if (id.length() || key.length()) {
        os << "RSA";
        PrintSecret(os << " Session-ID:", id);
        PrintSecret(os << " Master-Key:", key);
        os << "\n";
    }

    // CLIENT_RANDOM ... ...
    if (!suppressClientRandomReporting && (random.length() || key.length())) {
        os << "CLIENT_RANDOM ";
        PrintSecret(os, random);
        os << ' ';
        // we may have already printed the key on a separate Master-Key: line above,
        // but the CLIENT_RANDOM line format includes the same key info
        PrintSecret(os, key);
        os << "\n";
    }
}

std::ostream &
operator <<(std::ostream &os, const Security::HandshakeSecrets &secrets)
{
    secrets.record(os);
    return os;
}

#if USE_OPENSSL
/// Clears the given secret if it is likely to contain no secret information.
/// When asked for a secret too early, OpenSSL (successfully!) returns a copy of
/// the secret _storage_ (filled with zeros) rather than an actual secret.
static void
IgnorePlaceholder(SBuf &secret)
{
    static const auto NulChar = CharacterSet("NUL").add('\0');
    if (secret.findFirstNotOf(NulChar) == SBuf::npos) // all zeros
        secret.clear();
}

void
Security::HandshakeSecrets::getClientRandom(const Connection &sconn)
{
    random.clear();
    const auto expectedLength = SSL_get_client_random(&sconn, nullptr, 0);
    if (!expectedLength)
        return;

    // no auto due to reinterpret_casting of the result below
    char * const space = random.rawAppendStart(expectedLength);
    const auto actualLength = SSL_get_client_random(&sconn,
                              reinterpret_cast<unsigned char*>(space), expectedLength);
    random.rawAppendFinish(space, actualLength);

    IgnorePlaceholder(random);
}

void
Security::HandshakeSecrets::getSessionId(const Session &session)
{
    id.clear();
    unsigned int idLength = 0;
    // no auto due to reinterpret_casting of the result below
    const unsigned char * const idStart = SSL_SESSION_get_id(&session, &idLength);
    if (idStart && idLength)
        id.assign(reinterpret_cast<const char *>(idStart), idLength);

    IgnorePlaceholder(id);
}

void
Security::HandshakeSecrets::getMasterKey(const Session &session)
{
    key.clear();
    const auto expectedLength = SSL_SESSION_get_master_key(&session, nullptr, 0);
    if (!expectedLength)
        return;

    // no auto due to reinterpret_casting of the result below
    char * const space = key.rawAppendStart(expectedLength);
    const auto actualLength = SSL_SESSION_get_master_key(&session,
                              reinterpret_cast<unsigned char*>(space), expectedLength);
    key.rawAppendFinish(space, actualLength);

    IgnorePlaceholder(key);
}
#endif /* USE_OPENSSL */

/* Security::CommunicationSecrets */

void
Security::CommunicationSecrets::importFormatted(const char *formattedSecrets)
{
    libraryProvidedSecrets.append(formattedSecrets);
    // OpenSSL-provided lines are documented to lack a new line that is required
    // by NSS SSLKEYLOGFILE format. Adding a new line also simplifies secrets
    // concatenation/aggregation and printing code.
    libraryProvidedSecrets.append('\n');

    // Do not report two CLIENT_RANDOM lines, one provided to us by the library
    // and one hand-made by our handshakeSecrets-printing code.
    if (!handshakeSecrets.suppressClientRandomReporting &&
            strncmp(formattedSecrets, "CLIENT_RANDOM ", 14) == 0) {
        handshakeSecrets.suppressClientRandomReporting = true;
    }
}

SBuf
Security::CommunicationSecrets::exportFormatted(const Connection &sconn)
{
    SBuf newRecords = libraryProvidedSecrets;

    // Avoid unlimited accumulation while peers update secrets (and simplify).
    // We rely on the library supplying these secrets to filter out duplicates.
    libraryProvidedSecrets.clear();

    // Optimization: Avoid extracting handshakeSecrets once we gotAll() of them.
    // SSL_key_update() does not change Session-ID, Master-Key, CLIENT_RANDOM,
    // and SERVER_RANDOM values while adding CLIENT_TRAFFIC_SECRET_N and
    // SERVER_TRAFFIC_SECRET_N secrets. HandshakeSecrets may change if peers
    // renegotiate, but Squid has never had code to react to such renegotiation.
    // Such renegotiation ought to be disabled in earlier TLS protocol versions.
    // It is not supported starting with TLS v1.3. TLS v1.3 uses KeyUpdate
    // mechanism instead, but KeyUpdate does not change handshakeSecrets.
    if (!handshakeSecrets.gotAll() && handshakeSecrets.learnNew(sconn))
        newRecords.append(ToSBuf(handshakeSecrets));

    return newRecords;
}

