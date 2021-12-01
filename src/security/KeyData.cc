/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "fatal.h"
#include "security/CertGadgets.h"
#include "security/Io.h"
#include "security/KeyData.h"
#include "SquidConfig.h"
#include "ssl/bio.h"
#include "ssl/gadgets.h"

/**
 * Read certificate from file.
 * See also: Ssl::ReadX509Certificate function, gadgets.cc file
 */
bool
Security::KeyData::loadX509CertFromFile()
{
    debugs(83, DBG_IMPORTANT, "Using certificate in " << certFile);
    cert.reset(); // paranoid: ensure cert is unset

#if USE_OPENSSL
    const char *certFilename = certFile.c_str();
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file()));
    if (!bio || !BIO_read_filename(bio.get(), certFilename)) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate file '" << certFile << "': " << ErrorString(x));
        return false;
    }

    cert = Ssl::ReadX509Certificate(bio); // error detected/reported below

#elif USE_GNUTLS
    const char *certFilename = certFile.c_str();
    gnutls_datum_t data;
    Security::LibErrorCode x = gnutls_load_file(certFilename, &data);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate file '" << certFile << "': " << ErrorString(x));
        return false;
    }

    gnutls_pcert_st pcrt;
    x = gnutls_pcert_import_x509_raw(&pcrt, &data, GNUTLS_X509_FMT_PEM, 0);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to import certificate from '" << certFile << "': " << ErrorString(x));
        return false;
    }
    gnutls_free(data.data);

    gnutls_x509_crt_t certificate;
    x = gnutls_pcert_export_x509(&pcrt, &certificate);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to X.509 convert certificate from '" << certFile << "': " << ErrorString(x));
        return false;
    }

    if (certificate) {
        cert = Security::CertPointer(certificate, [](gnutls_x509_crt_t p) {
            debugs(83, 5, "gnutls_x509_crt_deinit cert=" << (void*)p);
            gnutls_x509_crt_deinit(p);
        });
    }

#else
    // do nothing.
#endif

    if (!cert) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate from '" << certFile << "'");
        return false;
    }

    selfSigned = CertIsSelfSigned(*cert.get());
    return true;
}

/**
 * Read certificate from file.
 * See also: Ssl::ReadX509Certificate function, gadgets.cc file
 */
void
Security::KeyData::loadX509ChainFromFile()
{
#if USE_OPENSSL
    const char *certFilename = certFile.c_str();
    Ssl::BIO_Pointer bio;
    if (!Ssl::OpenCertsFileForReading(bio, certFilename)) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load chain file '" << certFile << "': " << ErrorString(x));
        return;
    }

    debugs(83, DBG_PARSE_NOTE(3), "Using certificate chain in " << certFile);
    // and add to the chain any other certificate exist in the file
    CertList certsInFile;

    while (const auto ca = Ssl::ReadX509Certificate(bio)) {
        certsInFile.emplace_back(ca);
    }

    // OpenSSL sends certificate in the order they are stored in the chain
    // given to OpenSSL, so we must chain them in on-the-wire order.
    // RFC 8446 Section 4.4.2: "The sender's certificate MUST come in the first
    // CertificateEntry in the list.  Each following certificate SHOULD
    // directly certify the one immediately preceding it."
    CertPointer latestCert = cert;
    do {
        CertPointer anIssuer;
        if (CertIsSelfSigned(*latestCert.get())) {
            debugs(83, DBG_PARSE_NOTE(2), "CA " << CertSubjectName(*latestCert.get()) << " is self-signed, will not be chained.");
        } else {
            for (auto candidateIssuer = certsInFile.begin(); candidateIssuer != certsInFile.end(); ++candidateIssuer) {
                if (CertIsIssuedBy(*latestCert.get(), *candidateIssuer->get())) {
                    // We found an issuer add it to the chain.
                    debugs(83, DBG_PARSE_NOTE(3), "Adding issuer CA: " << CertSubjectName(*latestCert.get()));
                    anIssuer = CertPointer(*candidateIssuer);
                    chain.emplace_back(anIssuer);
                    certsInFile.erase(candidateIssuer);
                    break;
                }
            }
        }
        latestCert = anIssuer;
    } while (latestCert != nullptr);

#elif USE_GNUTLS
    // XXX: implement chain loading
    debugs(83, 2, "Loading certificate chain from PEM files not implemented in this Squid.");

#else
    // nothing to do.
#endif
}

/**
 * Read X.509 private key from file.
 */
bool
Security::KeyData::loadX509PrivateKeyFromFile()
{
    debugs(83, DBG_IMPORTANT, "Using key in " << privateKeyFile);

#if USE_OPENSSL
    const char *keyFilename = privateKeyFile.c_str();
    Ssl::BIO_Pointer bio;
    if (!Ssl::OpenCertsFileForReading(bio, keyFilename)) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load key file '" << keyFilename << "': " << ErrorString(x));
        return false;
    }
    // XXX: Ssl::AskPasswordCb needs SSL_CTX_set_default_passwd_cb_userdata()
    // so this may not fully work iff Config.Program.ssl_password is set.
    pem_password_cb *cb = ::Config.Program.ssl_password ? &Ssl::AskPasswordCb : nullptr;
    if (!Ssl::ReadPrivateKey(bio, pkey, cb)) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: '" << privateKeyFile << "' failed to load private key: " << ErrorString(x));
        return false;
    }

    Security::ForgetErrors();
    if (!X509_check_private_key(cert.get(), pkey.get())) {
        const auto x = ERR_get_error();
        const char *errStr =  x ? ErrorString(x) : "pkey/certificate mismatch";
        debugs(83, DBG_IMPORTANT, "ERROR: '" << privateKeyFile << "' checking private key failed: " << errStr);
        return false;
    }

#elif USE_GNUTLS
    const char *keyFilename = privateKeyFile.c_str();
    gnutls_datum_t data;
    if (gnutls_load_file(keyFilename, &data) == GNUTLS_E_SUCCESS) {
        gnutls_privkey_t key;
        (void)gnutls_privkey_init(&key);
        Security::ErrorCode x = gnutls_privkey_import_x509_raw(key, &data, GNUTLS_X509_FMT_PEM, nullptr, 0);
        if (x == GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_t xkey;
            gnutls_privkey_export_x509(key, &xkey);
            gnutls_privkey_deinit(key);
            pkey = Security::PrivateKeyPointer(xkey, [](gnutls_x509_privkey_t p) {
                debugs(83, 5, "gnutls_x509_privkey_deinit pkey=" << (void*)p);
                gnutls_x509_privkey_deinit(p);
            });
        }
    }
    gnutls_free(data.data);

#else
    // nothing to do.
#endif

    return bool(pkey);
}

void
Security::KeyData::loadFromFiles(const AnyP::PortCfg &port, const char *portType)
{
    char buf[128];
    if (!loadX509CertFromFile()) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' missing certificate in '" << certFile << "'");
        return;
    }

    // certificate chain in the PEM file is optional
    loadX509ChainFromFile();

    // pkey is mandatory, not having it makes cert and chain pointless.
    if (!loadX509PrivateKeyFromFile()) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' missing private key in '" << privateKeyFile << "'");
        cert.reset();
        chain.clear();
    }
}

