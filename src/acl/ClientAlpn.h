/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_CLIENTALPN_H
#define SQUID_SRC_ACL_CLIENTALPN_H

#include "acl/Node.h"

namespace Acl {

class ClientAlpn : public Acl::Node
{
    MEMPROXY_CLASS(ClientAlpn);

public:
    /* Acl::Node API */
    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty() const override;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_CLIENTALPN_H */

