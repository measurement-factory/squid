/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 52    URN Parsing */

#ifndef SQUID_SRC_URN_H
#define SQUID_SRC_URN_H

#include "log/forward.h"

class HttpRequest;
class StoreEntry;

void urnStart(HttpRequest *, StoreEntry *, const AccessLogEntryPointer &ale);

#endif /* SQUID_SRC_URN_H */

