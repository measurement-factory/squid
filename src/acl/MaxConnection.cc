/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/MaxConnection.h"
#include "client_db.h"
#include "debug/Stream.h"
#include "parser/Tokenizer.h"
#include "SquidConfig.h"

ACLMaxConnection::ACLMaxConnection (char const *theClass) : class_ (theClass), limit(-1)
{}

ACLMaxConnection::~ACLMaxConnection()
{}

char const *
ACLMaxConnection::typeString() const
{
    return class_;
}

bool
ACLMaxConnection::empty () const
{
    return false;
}

bool
ACLMaxConnection::valid () const
{
    return limit > 0;
}

void
ACLMaxConnection::parse()
{
    limit = atoi(ConfigParser::Current().requiredAclValue("maxconn number"));
}

int
ACLMaxConnection::match(ACLChecklist *checklist)
{
    return clientdbEstablished(Filled(checklist)->src_addr, 0) > limit ? 1 : 0;
}

SBufList
ACLMaxConnection::dump() const
{
    SBufList sl;
    if (!limit)
        return sl;

    SBuf s;
    s.Printf("%d", limit);
    sl.push_back(s);
    return sl;
}

void
ACLMaxConnection::prepareForUse()
{
    if (0 != Config.onoff.client_db)
        return;

    debugs(22, DBG_CRITICAL, "WARNING: 'maxconn' ACL (" << name << ") won't work with client_db disabled");
}

