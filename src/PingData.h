/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PINGDATA_H
#define SQUID_PINGDATA_H

class PeerSelectorWait;

class ping_data
{

public:
    ping_data();

    struct timeval start;
    struct timeval stop;
    int timeout;        /* msec */
    int timedout;
    int n_sent;

    PeerSelectorWait *peerWaiting; ///< preserves the context while waiting for ping replies
};

#endif /* SQUID_PINGDATA_H */

