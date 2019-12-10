/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "MasterXaction.h"

InstanceIdDefinitions(MasterXaction, "MXID_");

Stopwatch::Stopwatch():
    subtotal_(Clock::duration::zero())
{
    debugs(1,2, this);
}

Stopwatch::Clock::duration
Stopwatch::total() const
{
    auto result = subtotal_;
    if (running())
        result += Clock::now() - runStart_;
    return result;
}

Stopwatch::Clock::duration
Stopwatch::busyPeriodMean() const
{
    if (resumes_)
        return total()/resumes_;
    return Clock::duration::zero();
}

/// (re)starts or continues measuring as needed; must be paired with pause()
void
Stopwatch::resume()
{
    if (!running()) {
        runStart_ = Clock::now();
        debugs(1,2, this << ' ' << (resumes_+1) << " started after " << subtotal_.count() << "ns");
    }
    ++resumes_;
}

/// ends the current measurement period if needed; requires prior resume()
Stopwatch::Clock::duration
Stopwatch::pause()
{
    const auto runtime = Clock::now() - runStart_;
    ++pauses_;
    if (!running()) {
        subtotal_ += runtime;
        debugs(1,2, this << ' ' << pauses_ << " ran for " << runtime.count() << "ns");
    }
    return runtime;
}

