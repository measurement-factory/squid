/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_RANDOM_UUID_H
#define SQUID_SRC_BASE_RANDOM_UUID_H

#include <iosfwd>

/// 128-bit Universally Unique IDentifier (UUID), version 4 (variant 1).
/// These UUIDs are generated from pseudo-random numbers as defined by RFC 4122.
class RandomUuid
{
public:
    RandomUuid(); ///< creates a new unique ID (i.e. not a nil UUID)
    RandomUuid(RandomUuid &&) = default;
    RandomUuid &operator=(RandomUuid &&) = default;

    // (Implicit) copying of _unique_ IDs is prohibited to prevent accidents.
    // Use clone() instead.
    RandomUuid(const RandomUuid &) = delete;
    RandomUuid &operator=(const RandomUuid &) = delete;

    bool operator ==(const RandomUuid &) const;
    bool operator !=(const RandomUuid &other) const { return !(*this == other); }

    /// creates a UUID object with the same value as this UUID
    RandomUuid clone() const;

    // XXX: We should not create a UUID and then overwrite it by deserializing.
    /// De-serializes a UUID value from the given 128-bit storage. The length
    /// argument is for sanity checking and must be equal to 16 (i.e. 128 bits).
    void load(const void *data, size_t length);

    /// writes a human-readable version
    void print(std::ostream &os) const;

private:
    /// read/write access to storage bytes
    char *raw() { return reinterpret_cast<char*>(this); }
    /// read-only access to storage bytes
    const char *raw() const { return reinterpret_cast<const char*>(this); }

    /*
     * These field sizes and names come from RFC 4122 Section 4.1.2. They do not
     * accurately represent the actual UUID version 4 structure which, the six
     * version/variant bits aside, contains just random bits.
     */
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqHiAndReserved;
    uint8_t clockSeqLow;
    int8_t node[6];
};

#endif /* SQUID_SRC_BASE_RANDOM_UUID_H */

