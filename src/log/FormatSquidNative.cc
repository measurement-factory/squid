/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid format */

#include "squid.h"
#include "AccessLogEntry.h"
#include "format/Quoting.h"
#include "format/Token.h"
#include "globals.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidConfig.h"

void
Log::Format::SquidNative(const AccessLogEntry::Pointer &al, Logfile * logfile, const RecordTime &recordTime)
{
    char hierHost[MAX_IPSTRLEN];

    const char *user = nullptr;

#if USE_AUTH
    if (al->request && al->request->auth_user_request != nullptr)
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

    char clientip[MAX_IPSTRLEN];
    al->getLogClientIp(clientip, MAX_IPSTRLEN);

    const SBuf method(al->getLogMethod());

    const auto seconds = recordTime.systemSecondsEpoch();
    const auto ms = recordTime.systemMillisecondsFraction();
    auto trTime = al->cache.trTime(recordTime);

    logfilePrintf(logfile, "%9ld.%03d %6ld %s %s/%03d %" PRId64 " " SQUIDSBUFPH " " SQUIDSBUFPH " %s %s%s/%s %s%s",
                  seconds,
                  static_cast<int>(ms),
                  tvToMsec(trTime),
                  clientip,
                  al->cache.code.c_str(),
                  al->http.code,
                  al->http.clientReplySz.messageTotal(),
                  SQUIDSBUFPRINT(method),
                  SQUIDSBUFPRINT(al->url),
                  user ? user : dash_str,
                  al->hier.ping.timedout ? "TIMEOUT_" : "",
                  hier_code_str[al->hier.code],
                  al->hier.tcpServer != nullptr ? al->hier.tcpServer->remote.toStr(hierHost, sizeof(hierHost)) : "-",
                  al->http.content_type,
                  (Config.onoff.log_mime_hdrs?"":"\n"));

    safe_free(user);

    if (Config.onoff.log_mime_hdrs) {
        char *ereq = ::Format::QuoteMimeBlob(al->headers.request);
        MemBuf mb;
        mb.init();
        al->packReplyHeaders(mb);
        auto erep = ::Format::QuoteMimeBlob(mb.content());
        logfilePrintf(logfile, " [%s] [%s]\n", ereq, erep);
        safe_free(ereq);
        safe_free(erep);
    }
}

