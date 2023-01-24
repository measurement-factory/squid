/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Manager.h"
#include "anyp/ProtocolType.h"
#include "base/TextException.h"
#include "HttpRequest.h"
#include "sbuf/Stream.h"

SBufList
ACLManager::dump() const
{
    SBufList sl;
    sl.push_back(SBuf(name));
    return sl;
}

int
ACLManager::match(ACLChecklist *checklist)
{
    static const SBuf mgrPfx("/squid-internal-mgr/");
    const auto request = Filled(checklist)->request;
    return request->url.path().startsWith(mgrPfx) || request->url.getScheme() == AnyP::PROTO_CACHE_OBJECT;
}

void
ACLManager::parse()
{
    throw TextException(ToSBuf("cannot parse ACL ", name, " with pre-defined ", class_, " type"), Here());
}

void
ACLManager::prohibitTypeChange() const
{
    throw TextException(ToSBuf("ACL ", name, " already exists with a pre-defined type"), Here());
}
