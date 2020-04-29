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

/// absolute time in milliseconds, compatible with current_dtime
typedef unsigned long PingAbsoluteTime;

typedef std::multimap<PingAbsoluteTime, PeerSelector *, std::less<PingAbsoluteTime>, PoolingAllocator<std::pair<PingAbsoluteTime, PeerSelector *> > > PeerSelectorMap;
typedef PeerSelectorMap::iterator PeerSelectorMapIterator;

class ping_data
{

public:
    ping_data();

    PingAbsoluteTime expectedStopTime() const {
        return start.tv_sec*1000 + start.tv_usec/1000 + timeout;
    }

    struct timeval start;

    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    PingAbsoluteTime timeout;
    int timedout;
    int w_rtt;
    int p_rtt;

    PeerSelectorMapIterator waitPosition; ///< the position of this PeerSelector in the waiting map
};

#endif /* SQUID_PINGDATA_H */

