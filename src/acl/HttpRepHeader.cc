/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/HttpHeaderData.h"
#include "acl/HttpRepHeader.h"
#include "HttpReply.h"

int
ACLHTTPRepHeaderStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    // XXX: Cast to work around this branch lack of master/v7 commit 47c9c937:
    // Fix const-correctness of ACLHTTPHeaderData::match() parameter
    return data->match(const_cast<HttpHeader*>(&checklist->reply().header));
}

