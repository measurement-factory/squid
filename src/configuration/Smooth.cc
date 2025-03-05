/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "configuration/Preprocessor.h"
#include "configuration/Smooth.h"
#include "debug/Stream.h"

Configuration::SmoothReconfiguration::SmoothReconfiguration(const PreprocessedCfg &aConfig):
    freshConfig(aConfig)
{
    Assure(freshConfig.allowSmoothReconfiguration);
}

void
Configuration::SmoothReconfiguration::run()
{
    // Do not report the number of pliable and (unchanged) rigid directives:
    // Such reports may confuse admins because those numbers include
    // default-generated directives that admins do not see in their configs.
    // TODO: Report the number of non-generated directives.
    debugs(3, DBG_IMPORTANT, "Performing smooth reconfiguration");

    prepComponents();

    // TODO: Optimize by reconfiguring only those pliable directives that changed.
    for (const auto &directive: freshConfig.pliableDirectives)
        reconfigure(directive);

    finalizeComponents();

    // TODO: Close client-Squid and Squid-origin pconns, but only if relevant details change.

    finish();
}

void
Configuration::SmoothReconfiguration::finish()
{
    while (const auto call = plan_.extract())
        ScheduleCallHere(call);
}

