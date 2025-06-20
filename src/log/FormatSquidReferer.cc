/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid referer format */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"

void
Log::Format::SquidReferer(const AccessLogEntry::Pointer &al, Logfile * const logfile, const RecordTime &recordTime)
{
    const char *referer = nullptr;
    if (al->request)
        referer = al->request->header.getStr(Http::HdrType::REFERER);

    if (!referer || *referer == '\0')
        referer = "-";

    char clientip[MAX_IPSTRLEN];
    al->getLogClientIp(clientip, MAX_IPSTRLEN);

    const SBuf url = !al->url.isEmpty() ? al->url : ::Format::Dash;

    const auto seconds = recordTime.systemSecondsEpoch();
    const auto ms = recordTime.systemMillisecondsFraction();

    logfilePrintf(logfile, "%9ld.%03d %s %s " SQUIDSBUFPH "\n",
                  seconds,
                  static_cast<int>(ms),
                  clientip,
                  referer,
                  SQUIDSBUFPRINT(url));
}

