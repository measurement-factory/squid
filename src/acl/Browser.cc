/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Browser.h"
#include "acl/Checklist.h"
#include "acl/RegexData.h"

/* explicit template instantiation required for some systems */

template class ACLRequestHeaderStrategy<Http::HdrType::USER_AGENT>;
