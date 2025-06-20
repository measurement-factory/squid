/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOG_RECORDTIME_H
#define SQUID_SRC_LOG_RECORDTIME_H

#include "base/Stopwatch.h"

#include <utility>

/// the time when ALE record formatting starts
class RecordTime
{
public:
    RecordTime();

    auto legacySecondsAndMilliseconds() const { return std::pair(legacyTime.tv_sec, legacyTime.tv_usec / 1000); }

    /// record creation time for use with std::chrono-based logformat codes
    Stopwatch::Clock::time_point stopwatchTime;

    /// record creation time for use with logformat codes based on POSIX timeval et al.
    struct timeval legacyTime;
};

#endif /* SQUID_SRC_LOG_RECORDTIME_H */

