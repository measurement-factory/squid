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
class PeerSelectorTimeoutProcessor;

typedef std::pair<timeval, PeerSelector *> PeerSelectorMapItem;
typedef std::multimap<timeval, PeerSelector *, std::less<timeval>, PoolingAllocator<PeerSelectorMapItem > > PeerSelectorMap;
typedef PeerSelectorMap::iterator PeerSelectorMapIterator;

class ping_data
{

public:
    ping_data();

    /// the absolute time when the timeout will occur
    timeval expectedStopTime() const;

    struct timeval start;

    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    int timeout;        /* msec */
    int timedout;
    int w_rtt;
    int p_rtt;

private:
    friend PeerSelectorTimeoutProcessor;
    /// maintained by PeerSelectorTimeoutProcessor to keep our position its map
    PeerSelectorMapIterator waitPosition;
};

#endif /* SQUID_PINGDATA_H */

