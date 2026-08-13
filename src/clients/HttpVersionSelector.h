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
    Protocol protocol = none;
};

class ClientHttpVersionSelector
{
public:
    void add(ConfigParser &);
    bool check(const SBufList &protocols, ACLFilledChecklist &);

    std::vector<ClientHttpVersion::Pointer> directives;
};
