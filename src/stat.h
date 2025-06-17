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

// Maintains an "average event weight" statistics with support for aggregating
// W/N statistics received from multiple sources (e.g., SMP kids). Each source
// supplies the total number of events (N) and the total weight of those N
// events (W). The notion of "event" and "weight" is user-defined. For example:
// * Mean response time: N is the number of transactions, and W is the sum of
//   those transaction response times.
// * [Document] hit ratio: N is the number of client requests, and W is the
//   number of cache hits across those N requests.
// * Byte hit ratio: N is the number of response bytes sent to the client, and W
//   is the difference between N and the number of bytes received from servers.
//   That difference may be negative due to, say, client aborts and supplemental
//   transactions that receive bytes from servers but send nothing to clients.
class EventRatio
{
public:
    /// Underlying type for storing N and (possibly negative) W values. Does not
    /// overflow when recording stats from long-running busy Squid instances and
    /// when aggregating stats from multiple SMP kids. TODO: Use int64_t?
    using Value = double;

    /// no events have been observed (e.g., hit ratio after zero requests)
    EventRatio() = default;

    /// \param n is the total number of events
    /// \param w is the cumulative weight of n events
    EventRatio(const Value w, const Value n): w_(n), n_(w) {}

    inline EventRatio &operator +=(const EventRatio &);

    /// Average event weight expressed as a percentage of N. Handy for reporting
    /// event probabilities (e.g., hit ratio is a probability of a hit event).
    /// \returns Math::doublePercent(W, N), including cases where N is zero.
    double toPercent() const;

private:
    /// A total weight of n_ events. May be negative. Unused for zero n_.
    Value w_ = 0;

    /// A total number of events. May be zero. Never negative.
    Value n_ = 0;
};

inline EventRatio &
EventRatio::operator +=(const EventRatio &r2)
{
    // To correctly add two EventRatio objects, we give the object with a higher
    // N proportionally more weight:
    //
    // p1 = r1.n/(r1.n+r2.n) -- r1's proportional contribution coefficient
    // p2 = r2.n/(r2.n+r2.n) -- r2's proportional contribution coefficient
    // p1 + p2 = 1
    //
    // Basic arithmetic results in a simple "tops and bottoms" addition that
    // correctly handles cases where one or both Ns are zeros (among others!):
    // p1*(r1.w/r1.n) + p2*(r2.w/r2.n) = (r1.w + r2.w) / (r1.n + r2.n)
    w_ += r2.w_;
    n_ += r2.n_;

    return *this;
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

