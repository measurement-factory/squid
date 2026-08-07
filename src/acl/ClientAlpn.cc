/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/ClientAlpn.h"
#include "acl/FilledChecklist.h"

bool
Acl::ClientAlpn::empty() const
{
    return false;
}

void
Acl::ClientAlpn::parse()
{
    //TODO implement
}

int
Acl::ClientAlpn::match(ACLChecklist *cl)
{
    //TODO implement
    return 0;
}

SBufList
Acl::ClientAlpn::dump() const
{
    //TODO implement
    return SBufList();
}

char const *
Acl::ClientAlpn::typeString() const
{
    return "tls::client_alpn";
}

