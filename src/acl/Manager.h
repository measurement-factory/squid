/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMANAGER_H
#define SQUID_ACLMANAGER_H

#include "acl/Acl.h"

class ACLManager : public ACL
{
    MEMPROXY_CLASS(ACLManager);

public:
    ACLManager(char const *aClass) : class_(aClass) { context("manager", nullptr); }

    /* ACL API */
    char const *typeString() const override { return class_; }
    void parse() override;
    int match(ACLChecklist *checklist) override;
    bool requiresRequest() const override { return true; }
    SBufList dump() const override;
    bool empty () const override { return false; }
    void dumpAll(const char *, StoreEntry *) override;

private:
    void prohibitTypeChange() const override;

    char const *class_;
};

#endif

