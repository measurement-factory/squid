/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/CacheManagerCheck.h"
#include "acl/FilledChecklist.h"
#include "HttpRequest.h"
#include "internal.h"

Acl::CacheManagerCheck::CacheManagerCheck()
{
    context("manager", "built-in");
}

SBufList
Acl::CacheManagerCheck::dump() const
{
    return SBufList();
}

int
Acl::CacheManagerCheck::match(ACLChecklist * const checklist)
{
    // This check must match the one in internalStart().
    return ForThisCacheManager(*Filled(checklist)->request);
}

void
Acl::CacheManagerCheck::parse()
{
    assert(!"unreachable code: squid.conf syntax does not support built-in ACL types");
}

