/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLCACHEMANAGERCHECK_H
#define SQUID_ACLCACHEMANAGERCHECK_H

#include "acl/Acl.h"

namespace Acl {

class CacheManagerCheck : public ACL
{
    MEMPROXY_CLASS(CacheManagerCheck);

public:
    explicit CacheManagerCheck(char const *aClass) : class_(aClass) { context("manager", "built-in"); }
    ~CacheManagerCheck() override {}

    /* ACL API */
    char const *typeString() const override { return class_; }
    void parse() override;
    int match(ACLChecklist *checklist) override;
    bool requiresRequest() const override { return true; }
    SBufList dump() const override;
    bool empty() const override { return false; }
    void dumpAll(const char *, StoreEntry *) override;

private:

    char const *class_;
};

} // namespace Acl

#endif /* SQUID_ACLCACHEMANAGERCHECK_H */

