/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RegexPattern.h"
#include <utility>

RegexPattern::RegexPattern(int aFlags, const char *aPattern) :
    flags(aFlags),
    pattern(xstrdup(aPattern))
{
    memset(&regex, 0, sizeof(regex));
}

RegexPattern::RegexPattern(RegexPattern &&o) :
    flags(std::move(o.flags)),
    regex(std::move(o.regex)),
    pattern(std::move(o.pattern))
{
    memset(&o.regex, 0, sizeof(o.regex));
    o.pattern = nullptr;
}

RegexPattern::~RegexPattern()
{
    xfree(pattern);
    regfree(&regex);
}

bool
RegexPattern::match(const char *str, RegexMatch &regexMatch)
{
    // Must((flags & REG_NOSUB) == 0);
    if (regexec(&regex, str, regexMatch.maxGroups(), &regexMatch.groups[0], 0) == 0) {
        regexMatch.matchedString = SBuf(str);
        return true;
    }
    return false;
}

RegexPattern &
RegexPattern::operator =(RegexPattern &&o)
{
    flags = std::move(o.flags);
    regex = std::move(o.regex);
    memset(&o.regex, 0, sizeof(o.regex));
    pattern = std::move(o.pattern);
    o.pattern = nullptr;
    return *this;
}

int
RegexMatch::startOffset()
{
    Must(groups.size());
    return groups[0].rm_so;
}

int
RegexMatch::endOffset()
{
    Must(groups.size());
    return groups[0].rm_eo;
}

void
RegexMatch::clear()
{
    matchedString.clear();
    for (auto &group: groups) {
        group.rm_eo = 0;
        group.rm_so = 0;
    }
}

SBuf
RegexMatch::capture(const uint64_t captureNum) const {
    Must(captureNum < groups.size());
    Must(matchedString.length() > static_cast<SBuf::size_type>(groups[captureNum].rm_eo));
    return matchedString.substr(groups[captureNum].rm_so, groups[captureNum].rm_eo - groups[captureNum].rm_so);
}

