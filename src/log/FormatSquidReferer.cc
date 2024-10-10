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
Log::Format::SquidReferer(const AccessLogEntry::Pointer &al, Logfile *logfile)
{
    const char *referer = nullptr;
    if (al->request)
        referer = al->request->header.getStr(Http::HdrType::REFERER);

    if (!referer || *referer == '\0')
        referer = "-";

    char clientip[MAX_IPSTRLEN];
    al->getLogClientIp(clientip, MAX_IPSTRLEN);

    const SBuf url = !al->url.isEmpty() ? al->url : ::Format::Dash;

    using namespace std::chrono_literals;
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(al->formattingTime.time_since_epoch()).count();
    const auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(al->formattingTime.time_since_epoch());
    const auto ms = (totalMs % std::chrono::milliseconds(1s)).count();

    logfilePrintf(logfile, "%9ld.%03d %s %s " SQUIDSBUFPH "\n",
                  seconds,
                  static_cast<int>(ms),
                  clientip,
                  referer,
                  SQUIDSBUFPRINT(url));
}

