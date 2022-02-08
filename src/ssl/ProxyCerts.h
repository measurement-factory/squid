/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSLPROXYCERTS_H_
#define SQUID_SSLPROXYCERTS_H_

#if USE_OPENSSL
#include "acl/forward.h"

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
    char *param; ///< all adaptation algorithm parameters (as configured)
    char *param1; ///< the first parameter in multi-parameter algorithm config
    char *param2; ///< the second parameter in multi-parameter algorithm config
    ACLList *aclList;
    sslproxy_cert_adapt *next;
};
#endif

#endif /* SQUID_SSLPROXYCERTS_H_ */

