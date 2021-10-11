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

    const auto oldLevel = level();
    const auto product = IntegralProduct(oldLevel, rate.restore_bps, incr);
    if (product.has_value()) {
        const auto sum = IncreaseSum(oldLevel, product.value());
        if (sum.has_value()) {
            level() = sum.value();
            return;
        }
    }
    level() = rate.max_bytes;
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
    level() = (int) (((double)rate.max_bytes *
                      Config.Delay.initial) / 100);
}

#endif /* USE_DELAY_POOLS */

