/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PINGDATA_H
#define SQUID_PINGDATA_H

#include "mem/PoolingAllocator.h"

#include <map>

class PeerSelector;

typedef std::multimap<timeval, PeerSelector *, std::less<timeval>, PoolingAllocator<std::pair<timeval, PeerSelector *> > > PeerSelectorMap;
typedef PeerSelectorMap::iterator PeerSelectorMapIterator;

class ping_data
{

public:
    ping_data();

    void expectedStopTime(timeval &result) const {
        struct timeval timeInterval;
        timeInterval.tv_sec = timeout / 1000;
        timeInterval.tv_usec = (timeout % 1000) * 1000;

        tvAdd(result, start, timeInterval);
    }

    struct timeval start;

    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    int timeout;
    int timedout;
    int w_rtt;
    int p_rtt;

    PeerSelectorMapIterator waitPosition; ///< the position of this PeerSelector in the waiting map
};

#endif /* SQUID_PINGDATA_H */

