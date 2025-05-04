/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid ICAP Logging */

#include "squid.h"

#if ICAP_CLIENT

#include "AccessLogEntry.h"
#include "format/Quoting.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidConfig.h"

void
Log::Format::SquidIcap(const AccessLogEntry::Pointer &al, Logfile * logfile, const RecordTime &recordTime)
{
    const char *user = nullptr;
    char tmp[MAX_IPSTRLEN], clientbuf[MAX_IPSTRLEN];

    const auto client = al->getLogClientFqdn(clientbuf, sizeof(clientbuf));

#if USE_AUTH
    if (al->request != nullptr && al->request->auth_user_request != nullptr)
        user = ::Format::QuoteUrlEncodeUsername(al->request->auth_user_request->username());
#endif

    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->getExtUser());

#if USE_OPENSSL
    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->cache.ssluser);
#endif

    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->getClientIdent());

    if (user && !*user)
        safe_free(user);

    const auto seconds = recordTime.systemSecondsEpoch();
    const auto ms = recordTime.systemMillisecondsFraction();
    auto icapTrTime = al->icap.trTime(recordTime);

    logfilePrintf(logfile, "%9ld.%03d %6ld %s %s/%03d %" PRId64 " %s %s %s -/%s -\n",
                  seconds,
                  static_cast<int>(ms),
                  tvToMsec(icapTrTime),
                  client,
                  al->icap.outcome,
                  al->icap.resStatus,
                  al->icap.bytesRead,
                  Adaptation::Icap::ICAP::methodStr(al->icap.reqMethod),
                  al->icap.reqUri.termedBuf(),
                  user ? user : "-",
                  al->icap.hostAddr.toStr(tmp, MAX_IPSTRLEN));
    safe_free(user);
}
#endif

