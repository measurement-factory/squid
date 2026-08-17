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
#include <optional>
#include <string_view>

class ClientHttpVersion
{
public:
    using Pointer = std::shared_ptr<ClientHttpVersion>;

    enum Protocol { none, http11, h2, any };

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
    void add(ConfigParser &);
    std::optional<std::string_view> check(ACLFilledChecklist &ch);
    std::optional<std::string_view> check(const char *, unsigned int, ACLFilledChecklist &);

    bool supported(const char *proto, unsigned int protoLen) const;

    std::vector<ClientHttpVersion::Pointer> directives;
};
