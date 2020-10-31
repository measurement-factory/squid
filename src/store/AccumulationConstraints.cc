/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "SquidConfig.h"
#include "store/AccumulationConstraints.h"

void
Store::AccumulationConstraints::enforceHardMaximum(const uint64_t hardMax, const char * const reason)
{
    // Ignore parserMinimum_, even when it exceeds hardMax: Incoming data often
    // passes through a serious of buffers. Our parserMinimum_ is based on the
    // first (parsing) buffer, which may be empty. The hard maximum often
    // protects the last (BodyPipe) buffer, which may be full. We cannot
    // overflow any buffer and lack code to split data between the two buffers
    // (see commit 254f393), so we stall parsing (honoring hard maximum) and
    // hope that, when a full buffer is drained, the caller will be notified and
    // will resume reading (hence, eventually satisfying parserMinimum_).

    if (hardMax < allowance_) {
        debugs(19, 5, "enforcing " << hardMax << " for " << reason << "; was: " << allowance_);
        allowance_ = hardMax;
    } else if (hardMax == allowance_) {
        debugs(19, 7, "confirming " << hardMax << " for " << reason);
    } else {
        debugs(19, 7, "ignoring " << hardMax << " for " << reason << "; enforcing " << allowance_);
    }
}

void
Store::AccumulationConstraints::enforceParserProgress(const size_t bytesBuffered, const size_t lookAheadMinimum)
{
    assert(!parserMinimum_); // no (need to) support multiple calls
    if (bytesBuffered < lookAheadMinimum) {
        parserMinimum_ = lookAheadMinimum - bytesBuffered;
        debugs(19, 5, parserMinimum_ << '=' << lookAheadMinimum << '-' << bytesBuffered);
        // parserMinimum_ can only be enforced via enforceReadAheadLimit()
    } else {
        // buffered bytes already satisfy the look-ahead minimum
        debugs(19, 7, "0: " << lookAheadMinimum << "<=" << bytesBuffered);
    }
}

void
Store::AccumulationConstraints::enforceReadAheadLimit(const int64_t currentGap)
{
    assert(Config.readAheadGap >= 0);
    assert(!ignoreReadAheadGap);

    const auto gapDiff = Config.readAheadGap - currentGap;
    debugs(19, 7, "gapDiff=" << gapDiff << '=' << Config.readAheadGap << '-' << currentGap <<
           "; parserMinimum_=" << parserMinimum_);
    static_assert(std::is_signed<decltype(gapDiff)>::value,
                  "gapDiff supports a 'buffered too much' state");

    // avoid negative results and obey parser restrictions
    if (gapDiff <= 0)
        return enforceHardMaximum(parserMinimum_, "buffered too much");

    const auto gapMaximum = static_cast<uint64_t>(gapDiff);
    if (gapMaximum < parserMinimum_)
        return enforceHardMaximum(parserMinimum_, "anything smaller may stall parsing");

    assert(gapMaximum > 0);
    debugs(19, 5, gapMaximum << " >= " << parserMinimum_);
    return enforceHardMaximum(gapMaximum, "read_ahead_gap");
}
