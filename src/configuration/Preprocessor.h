/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CONFIGURATION_PREPROCESSOR_H
#define SQUID_SRC_CONFIGURATION_PREPROCESSOR_H

#include "configuration/forward.h"
#include "sbuf/forward.h"

namespace Configuration {

/// Interprets Squid configuration up to (and excluding) parsing of individual
/// directives. Provides configuration parser with a sequence of directives to
/// parse, including various defaults. Facilitates partial reconfiguration.
/// Preprocessor operations do not affect current Squid configuration.
class Preprocessor
{
public:
    // XXX: Document
    int process(const char * const filename);

private:
    int processFile(const char *filename, size_t depth);
    int processIncludedFiles(const SBuf &paths, size_t depth);

    void default_line(const char *s);

    /* all methods below are defined in cf_parser.cci generated by cf_gen.cc */

    static bool ValidDirectiveName(const SBuf &);

    void processInitialDefaults();
    void processIfNoneDefaults();
    void processPostscriptumDefaults();
};

} // namespace Configuration

#endif /* SQUID_SRC_CONFIGURATION_PREPROCESSOR_H */

