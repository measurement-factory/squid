/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_CACHEMANAGERCHECK_H
#define SQUID_SRC_ACL_CACHEMANAGERCHECK_H

#include "acl/Acl.h"

namespace Acl {

class CacheManagerCheck : public ACL
{
    MEMPROXY_CLASS(CacheManagerCheck);

public:
    CacheManagerCheck();
    ~CacheManagerCheck() override {}

    /* ACL API */
    char const *typeString() const override { return "built-in manager ACL"; }
    void parse() override;
    int match(ACLChecklist *) override;
    bool requiresRequest() const override { return true; }
    SBufList dump() const override;
    bool empty() const override { return false; }
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_CACHEMANAGERCHECK_H */

