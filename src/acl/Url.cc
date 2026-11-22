/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Url.h"
#include "anyp/Uri.h"
#include "HttpRequest.h"

int
Acl::UrlCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);
    // Manager ACL: prohibit user info altogether because the regex is vulnerable
    // to attacks with URLs having user info with percent-encoded sequences
    const auto uri = name.cmp("manager") == 0 ?
            checklist->request->url.createAbsolute(false) :
            checklist->request->effectiveRequestUri();
    // TODO: Consider refactoring so that effectiveRequestUri() returns decoded URI.
    return data->match(AnyP::Uri::DecodeOrDupe(uri).c_str());
}

