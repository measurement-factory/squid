/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "sbuf/SBuf.h"
#include "security/CertGadgets.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

SBuf
Security::CertSubjectName(Certificate &cert)
{
    SBuf out;
#if USE_OPENSSL
    X509_NAME *name = X509_get_subject_name(&cert);
    if (!name) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName");
        return out;
    }
    out = Ssl::X509NameToSBuf(name);
#elif USE_GNUTLS
    gnutls_x509_dn_t dn;
    auto x = gnutls_x509_crt_get_subject(&cert, &dn);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName: " << Security::ErrorString(x));
        return out;
    }

    gnutls_datum_t str;
    x = gnutls_x509_dn_get_str(dn, &str);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot describe certificate SubjectName: " << Security::ErrorString(x));
        return out;
    }
    out.append(reinterpret_cast<const char *>(str.data), str.size);
    gnutls_free(str.data);

#else
    debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName, no TLS library is configured");
    return out;
#endif

    debugs(83, DBG_PARSE_NOTE(3), "found cert subject=" << out);
    return out;
}

bool
Security::CertIsIssuedBy(Certificate &cert, Certificate &issuer)
{
    Debug::Levels[83] = 9;
#if USE_OPENSSL
    const auto result = X509_check_issued(&issuer, &cert);
    if (result == X509_V_OK)
        return true;
    debugs(83, DBG_PARSE_NOTE(3), CertSubjectName(issuer) << " did not sign " <<
           CertSubjectName(cert) << ": " << X509_verify_cert_error_string(result) << " (" << result << ")");
#elif USE_GNUTLS
    const auto result = gnutls_x509_crt_check_issuer(&cert, &issuer);
    if (result == 1)
        return true;
    debugs(83, DBG_PARSE_NOTE(3), CertSubjectName(issuer) << " did not sign " << CertSubjectName(cert));
#else
    debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot determine certificates relationship, no TLS library is configured");
#endif
    return false;
}
