/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 18    Cache Manager Statistics */

#ifndef SQUID_STAT_H_
#define SQUID_STAT_H_

// TODO: Rephrase to support negative tops (and bottoms?) as in byte hit ratios.
/// Maintains totals for events that are divided into two mutually exclusive
/// categories (e.g., cache hits/misses or busy/idle time). One of the two
/// categories is treated as "primary" for the purposes of computing event
/// ratios (e.g., hit ratio or busy time percentage). Each event is associated
/// with an integer "value" or "weight".
class EventRatio
{
public:
    using Value = double;

    /// no events have been observed (e.g., hit ratio after zero requests)
    EventRatio() = default;

    /// \param primary is the cumulative weight of events in primary category
    /// \param total is the cumulative weight of events in all categories
    EventRatio(const Value primary, const Value total): primary_(primary), total_(total) {}

    // TODO: Check whether this can be removed.
    /// whether any events have been observed, allowing this ratio to be
    /// accurately represented by a single non-negative number
    explicit operator bool() const { return bool(total_); }

    /// represents primary value as a percentage of the total
    /// \returns 100*primary/total for non-zero totals
    /// \returns noEventsValue for zero totals
    double toPercentOr(double noEventsValue) const;

// XXX private:
    Value primary_ = 0;
    Value total_ = 0;
};

inline EventRatio &
operator +=(EventRatio &r1, const EventRatio &r2)
{
    // "Tops and bottoms" addition. The usual fractions addition does not work
    // for event ratios. For example, if both workers received only hits, then
    // an SMP Squid instance document hit ratio is 100% rather than 200% that
    // adding n/n and m/m fractions would have yielded. Similarly, dividing
    // the usual fractions sum by the number of fractions yields wrong ratios:
    // (1000/1000 + 1/10)/2 = 55% compared to ~99% actual instance hit ratio.
    r1.primary_ += r2.primary_;
    r1.total_ += r2.total_;
    return r1;
}

void statInit(void);
double median_svc_get(int, int);
void pconnHistCount(int, int);
int stat5minClientRequests(void);
double stat5minCPUUsage(void);
EventRatio statRequestHitRatio(int minutes);
EventRatio statRequestHitMemoryRatio(int minutes);
EventRatio statRequestHitDiskRatio(int minutes);
EventRatio statByteHitRatio(int minutes);

class StatCounters;
StatCounters *snmpStatGet(int);

#endif /* SQUID_STAT_H_ */

