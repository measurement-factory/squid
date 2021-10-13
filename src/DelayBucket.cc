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
    // make sure an undefined IntegralProduct() result (below) implies overflow
    if (rate.restore_bps < 0)
        return;

    const auto oldLevel = level();
    if (const auto delta = IntegralProduct(oldLevel, rate.restore_bps, incr)) {
        if (const auto newLevel = IncreaseSum(oldLevel, delta.value())) {
            level() = newLevel.value();
            return;
        }
    }
    // TODO: level() and rate.max_bytes should have the same type
    const auto maxLevel = IncreaseSum(BucketLevel(0), rate.max_bytes);
    assert(maxLevel);
    level() = maxLevel.value();
}

DelayBucket::BucketLevel
DelayBucket::bytesWanted(BucketLevel minimum, BucketLevel maximum) const
{
    BucketLevel result = max(minimum, min(maximum, level()));
    return result;
}

void
DelayBucket::bytesIn(BucketLevel qty)
{
    level() -= qty;
}

void
DelayBucket::init(DelaySpec const &rate)
{
    const auto initialLevel = IncreaseSum(BucketLevel(0), rate.max_bytes * (Config.Delay.initial/100.));
    assert(initialLevel);
    level() = initialLevel.value();
}

#endif /* USE_DELAY_POOLS */

