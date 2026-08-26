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
#include <string_view>

class ClientHttpVersion
{
public:
    using Pointer = std::shared_ptr<ClientHttpVersion>;

    explicit ClientHttpVersion(ConfigParser &);
    ~ClientHttpVersion();

    // prohibit copy and move
    ClientHttpVersion(const ClientHttpVersion&) = delete;
    ClientHttpVersion& operator=(const ClientHttpVersion&) = delete;

    void print(std::ostream &) const;

    ACLList *aclList = nullptr;
    SBuf protocol;
};

class ClientHttpVersionSelector
{
public:
    inline static const SBuf AnyProtocol = SBuf("any");
    inline static const SBuf Http11Protocol = SBuf("http/1.1");

    void add(ConfigParser &);

    /// Checks client_http_version directive when ALPN is available.
    /// \param alpn the string containing client's offered ALPN protocols in format:
    /// [len][string][len][string]... (e.g., \x02h2\x08http/1.1)
    /// \param alpnLen the length of alpn
    static const std::optional<SBuf> Check(ACLFilledChecklist *, const char *alpn, unsigned int alpnLen);

    std::vector<ClientHttpVersion::Pointer> directives;

private:

    const std::optional<SBuf> check(const char *in, unsigned int inLen, ACLFilledChecklist &);
};
