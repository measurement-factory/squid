/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "configuration/Preprocessor.h"
#include "debug/Stream.h"
#include "SquidConfig.h"

int
Configuration::Preprocessor::process(const char * const filename)
{
    debugs(3, DBG_PARSE_NOTE(2), "preprocessing defaults and " << filename);
    processInitialDefaults();
    const auto unrecognizedDirectives = processFile(filename, 0);
    processIfNoneDefaults();
    processPostscriptumDefaults();
    return unrecognizedDirectives;
}
