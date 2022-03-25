/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_RANDOM_UUID_H
#define SQUID_SRC_BASE_RANDOM_UUID_H

#include <iostream>

// RFC4122: Universally Unique IDentifier (UUID)
class RandomUuid
{
public:
    RandomUuid();
    RandomUuid(const RandomUuid &) = delete;
    RandomUuid &operator=(const RandomUuid &) = delete;
    RandomUuid(RandomUuid &&) = default;
    RandomUuid &operator=(RandomUuid &&) = default;

    void print(std::ostream &os) const;
    bool operator==(const RandomUuid&) const;
    bool operator!=(const RandomUuid &other) const { return !(*this == other); }
    RandomUuid clone() const;
    void load(const void *data, size_t length);

private:
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqHiAndReserved;
    uint8_t clockSeqLow;
    int8_t node[6];
};

#endif /* SQUID_SRC_BASE_RANDOM_UUID_H */

