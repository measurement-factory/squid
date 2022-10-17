/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_PROXYCERTS_H
#define SQUID_SRC_SSL_PROXYCERTS_H

#if USE_OPENSSL
#include "acl/forward.h"
#include "acl/Gadgets.h"
#include "security/forward.h"
#include "ssl/gadgets.h"

class sslproxy_cert_sign
{
public:
    sslproxy_cert_sign() = default;
    sslproxy_cert_sign(sslproxy_cert_sign &&) = delete; // prohibit all copy/move
    ~sslproxy_cert_sign() {
        while (const auto first = next) {
            next = first->next;
            first->next = nullptr;
            delete first;
        }
        if (aclList)
            aclDestroyAclList(&aclList);
    }

public:
    Ssl::CertSignAlgorithm alg = Ssl::algSignEnd;
    ACLList *aclList = nullptr;
    sslproxy_cert_sign *next = nullptr;
};

class sslproxy_cert_adapt
{
public:
    sslproxy_cert_adapt() = default;
    sslproxy_cert_adapt(sslproxy_cert_adapt &&) = delete; // prohibit all copy/move
    ~sslproxy_cert_adapt() {
        while (const auto first = next) {
            next = first->next;
            first->next = nullptr;
            delete first;
        }
        xfree(param);
        xfree(param1);
        xfree(param2);
        if (aclList)
            aclDestroyAclList(&aclList);
    }

public:
    Ssl::CertAdaptAlgorithm alg = Ssl::algSetEnd;
    char *param = nullptr; ///< all adaptation algorithm parameters (as configured)
    char *param1 = nullptr; ///< the first parameter in multi-parameter algorithm config
    char *param2 = nullptr; ///< the second parameter in multi-parameter algorithm config

    /// CheckValidityRangeFreshness() can do nothing until this time
    mutable time_t nextValidityRangeFreshnessCheck = 0;

    ACLList *aclList = nullptr;
    sslproxy_cert_adapt *next = nullptr;
};

// TODO: Move to the future sslproxy_cert_adapt setValidityRange setter/getter.
/// Informs of stale sslproxy_cert_adapt setValidityRange configuration. Once.
/// Should be called whenever setValidityRange is used, and not just at
/// configuration time, because the range can go stale while Squid is running.
void CheckValidityRangeFreshness(sslproxy_cert_adapt &, const Security::Time &from, const Security::Time &to);

#endif

#endif /* SQUID_SRC_SSL_PROXYCERTS_H */

