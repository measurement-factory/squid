/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_CONFIG_H
#define SQUID_SRC_SSL_CONFIG_H

#include "helper/ChildConfig.h"

namespace Ssl
{

class Config
{
public:
    enum BumpedXFFMode {xffNone = 0, xffTunnel, xffFollowXForwaredFor};

#if USE_SSL_CRTD
    char *ssl_crtd; ///< Name of external ssl_crtd application.
    /// The number of processes spawn for ssl_crtd.
    ::Helper::ChildConfig ssl_crtdChildren;
#endif
    char *ssl_crt_validator;
    ::Helper::ChildConfig ssl_crt_validator_Children;
#if FOLLOW_X_FORWARDED_FOR
    BumpedXFFMode bumped_traffic_indirect_client_address;
#endif

    Config();
    ~Config();
private:
    Config(const Config &); // not implemented
    Config &operator =(const Config &); // not implemented
};

extern Config TheConfig;

} // namespace Ssl
#endif /* SQUID_SRC_SSL_CONFIG_H */

