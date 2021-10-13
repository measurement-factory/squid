/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSOURCEDOMAIN_H
#define SQUID_ACLSOURCEDOMAIN_H
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategy.h"
#include "dns/forward.h"

class ACLSourceDomainStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACLSOURCEDOMAIN_H */

