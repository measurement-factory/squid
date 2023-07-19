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


SBufList
Acl::CacheManagerCheck::dump() const
{
    Assure(!"unreachable code: built-in ACLs cannot be represented using squid.conf syntax");
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
    throw TextException(ToSBuf("cannot parse built-in ACL ", name), Here());
}

void
Acl::CacheManagerCheck::dumpAll(const char *, StoreEntry *)
{
    debugs(3, 7, "no configuration to dump for built-in ACL " << name);
}
