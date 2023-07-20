/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 76    Internal Squid Object handling
 * AUTHOR: Duane, Alex, Henrik
 */

#ifndef SQUID_INTERNAL_H_
#define SQUID_INTERNAL_H_

#include "comm/forward.h"
#include "log/forward.h"
#include "sbuf/forward.h"

class HttpRequest;
class StoreEntry;

void internalStart(const Comm::ConnectionPointer &clientConn, HttpRequest *, StoreEntry *, const AccessLogEntryPointer &);
bool internalCheck(const SBuf &urlPath);
bool internalStaticCheck(const SBuf &urlPath);
char *internalLocalUri(const char *dir, const SBuf &name);
char *internalRemoteUri(bool, const char *, unsigned short, const char *, const SBuf &);
const char *internalHostname(void);
int internalHostnameIs(const char *);

/// whether the given request URL path points to a cache manager (not
/// necessarily running on this Squid instance)
bool ForSomeCacheManager(const SBuf &);

// TODO: Reduce "instance" to just the listening port (that received the
// request) by making flags.internal false for requests that (target getMyPort()
// but) do not target Squid listening port they were received on.
/// Whether the given request targets the cache manager running on this Squid
/// instance. Whether the built-in "manager" ACL should match. The two
/// conditions must yield identical results for any given request.
bool ForThisCacheManager(const HttpRequest &);

#endif /* SQUID_INTERNAL_H_ */

