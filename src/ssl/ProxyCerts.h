/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSLPROXYCERTS_H_
#define SQUID_SSLPROXYCERTS_H_

#if USE_OPENSSL
#include "acl/forward.h"
#include "security/forward.h"

class sslproxy_cert_sign
{
public:
    int alg;
    ACLList *aclList;
    sslproxy_cert_sign *next;
};

// TODO: Convert to a class that manages its components lifetime (at least)
class sslproxy_cert_adapt
{
public:
    int alg;

    /// CheckValidityRangeFreshness() can do nothing until this time
    mutable time_t nextValidityRangeFreshnessCheck;

    char *param; ///< all adaptation algorithm parameters (as configured)
    char *param1; ///< the first parameter in multi-parameter algorithm config
    char *param2; ///< the second parameter in multi-parameter algorithm config
    ACLList *aclList;
    sslproxy_cert_adapt *next;
};

// TODO: Move to the future sslproxy_cert_adapt setValidityRange setter/getter.
/// Informs of stale sslproxy_cert_adapt setValidityRange configuration. Once.
/// Should be called whenever setValidityRange is used, and not just at
/// configuration time, because the range can go stale while Squid is running.
void CheckValidityRangeFreshness(sslproxy_cert_adapt &, const Security::Time &from, const Security::Time &to);

#endif

#endif /* SQUID_SSLPROXYCERTS_H_ */

