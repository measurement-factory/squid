/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"
#include <base/Optional.h>

#if USE_DELAY_POOLS
#include "DelayBucket.h"
#include "DelaySpec.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "Store.h"

void
DelayBucket::stats(StoreEntry *entry)const
{
    storeAppendPrintf(entry, "%d", level());
}

void
DelayBucket::update(DelaySpec const &rate, int incr)
{
    if (rate.restore_bps == -1)
        return;

    if (const auto delta = IncreaseProduct(rate.restore_bps, incr)) {
        if (const auto newLevel = IncreaseSum(level_, delta.value())) {
            level_ = newLevel.value();
            return;
        }
    }
    // TODO: level() and rate.max_bytes should have the same type
    SetToNaturalSumOrMax(level_, rate.max_bytes);
}

int
DelayBucket::bytesWanted(int minimum, int maximum) const
{
    int result = max(minimum, min(maximum, level()));
    return result;
}

void
DelayBucket::bytesIn(int qty)
{
    level() -= qty;
}

void
DelayBucket::init(DelaySpec const &rate)
{
    SetToNaturalSumOrMax(level_, rate.max_bytes, Config.Delay.initial);
    // getting around possible integer overflows without turning to floats
    if (level_ < MaxValue(level_)) {
        level_ /= 100;
    } else {
        // Config.Delay.initial is always <= 100
        SetToNaturalSumOrMax(level_, rate.max_bytes/100, Config.Delay.initial);
    }
}

#endif /* USE_DELAY_POOLS */

