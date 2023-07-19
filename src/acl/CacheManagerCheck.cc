/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/CacheManagerCheck.h"
#include "acl/FilledChecklist.h"
#include "anyp/ProtocolType.h"
#include "base/TextException.h"
#include "HttpRequest.h"
#include "internal.h"
#include "sbuf/Stream.h"

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
    const auto request = Filled(checklist)->request;
    return request->url.getScheme() == ForThisCacheManager(request);
}

void
Acl::CacheManagerCheck::parse()
{
    Assure(!"unreachable code: squid.conf syntax does not support built-in ACL types");
}

void
Acl::CacheManagerCheck::dumpAll(const char *, StoreEntry *)
{
    debugs(3, 7, "built-in ACLs have no squid.conf definition: " << name);
}
