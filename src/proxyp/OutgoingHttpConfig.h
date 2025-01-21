/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PROXYP_OUTGOING_HTTP_CONFIG_H
#define SQUID_SRC_PROXYP_OUTGOING_HTTP_CONFIG_H

#include <acl/forward.h>

#include <iosfwd>

class ConfigParser;

namespace ProxyProtocol {

/// an http_outgoing_proxy_protocol irective configuration
class OutgoingHttpConfig
{
public:
    explicit OutgoingHttpConfig(ConfigParser &);

    void dump(std::ostream &);

    /// restrict logging to matching transactions
    ACLList *aclList = nullptr;
};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOING_HTTP_CONFIG_H */

