/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "acl/forward.h"
#include "configuration/forward.h"

#include <memory>

class ClientHttpVersionSelector
{
public:
    static const SBuf Http11Protocol;
    static const SBuf Http2Protocol;
    static const SBuf AnyProtocol;

    enum Protocol { http11, h2, any };

    void parse(ConfigParser &);

    /// Applies client_http_version rule to select a suitable protocol.
    /// \param alpn the string containing client's offered ALPN protocols (or nil) in format:
    /// [len][string][len][string]... (e.g., \x02h2\x08http/1.1)
    /// \param alpnLen the length of alpn
    static const std::optional<SBuf> Check(ACLFilledChecklist *, const char *alpn, unsigned int alpnLen);

    std::shared_ptr<ACLList> aclList;
};
