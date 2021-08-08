/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_REGEXPATTERN_H
#define SQUID_SRC_BASE_REGEXPATTERN_H

#include "compat/GnuRegex.h"
#include "mem/forward.h"
#include "sbuf/SBuf.h"

#include <vector>

/**
 * A regular expression,
 * plain text and compiled representations
 */
class RegexPattern
{
    MEMPROXY_CLASS(RegexPattern);

public:
    RegexPattern() = delete;
    RegexPattern(int aFlags, const char *aPattern);
    ~RegexPattern();

    // regex type varies by library, usually not safe to copy
    RegexPattern(const RegexPattern &) = delete;
    RegexPattern &operator =(const RegexPattern &) = delete;

    RegexPattern(RegexPattern &&);
    RegexPattern &operator =(RegexPattern &&);

    const char * c_str() const {return pattern;}
    bool match(const char *str) const {return regexec(&regex,str,0,NULL,0)==0;}

    /// Match str against the expression with maximum maxGroups sub-expressions.
    /// The result is stored in the groups array.
    bool match(const char *str, const int maxGroups);

    /// the matched sub-expression an captureNum position
    SBuf capture(const uint64_t captureNum) const;

public:
    int flags;
    regex_t regex;
    /// matched sub-expression list after the last match(str, maxGroups) call
    std::vector<regmatch_t> groups;

private:
    char *pattern;
};

#endif /* SQUID_SRC_BASE_REGEXPATTERN_H */

