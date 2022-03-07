/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef RANDOM_UUID_H
#define RANDOM_UUID_H

#include <iostream>

// RFC4122: Universally Unique IDentifier (UUID)
class RandomUuid
{
public:
    RandomUuid();
    void print(std::ostream &os);

private:
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqHiAndReserved;
    uint8_t clockSeqLow;
    int8_t node[6];
};

#endif

