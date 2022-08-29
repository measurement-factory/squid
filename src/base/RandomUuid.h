/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_RANDOMUUID_H
#define SQUID_SRC_BASE_RANDOMUUID_H

#include <sbuf/SBuf.h>

#include <array>
#include <iosfwd>

/// 128-bit Universally Unique IDentifier (UUID), version 4 (variant 1) as
/// defined by RFC 4122. These UUIDs are generated from pseudo-random numbers.
class RandomUuid
{
public:
    /// UUID representation independent of machine byte-order architecture
    using Serialized = std::array<uint8_t, 128/8>;

    /// creates a new unique ID (i.e. not a "nil UUID" in RFC 4122 terminology)
    RandomUuid();

    /// imports a UUID value that was exported using the serialize() API
    explicit RandomUuid(const Serialized &);

    RandomUuid(RandomUuid &&) = default;
    RandomUuid &operator=(RandomUuid &&) = default;

    // (Implicit) public copying is prohibited to prevent accidental duplication
    // of supposed-to-be-unique values. Use clone() when duplication is needed.
    RandomUuid &operator=(const RandomUuid &) = delete;

    /// exports UUID value; suitable for long-term storage
    Serialized serialize() const;

    bool operator ==(const RandomUuid &) const;
    bool operator !=(const RandomUuid &other) const { return !(*this == other); }

    /// creates a UUID object with the same value as this UUID
    RandomUuid clone() const { return *this; }

    /// writes a human-readable representation
    void print(std::ostream &os) const;

private:
    RandomUuid(const RandomUuid &) = default;

    /// read/write access to storage bytes
    char *raw() { return reinterpret_cast<char*>(this); }

    /// read-only access to storage bytes
    const char *raw() const { return reinterpret_cast<const char*>(this); }

    /// whether this (being constructed) object follows UUID version 4 variant 1 format
    bool sane() const;

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
    uint8_t node[6];
};

std::ostream &operator<<(std::ostream &os, const RandomUuid &uuid);

// TODO: move to a separate header
/// Variant entry attributes
class VaryDetails
{

public:
    /// constructs details for a leaf entry
    VaryDetails(const SBuf &h, const RandomUuid &id):
        headers_(h), uuid_(id.clone()) {}

    /// constructs details for a base entry
    explicit VaryDetails(const RandomUuid &id):
        uuid_(id.clone()) {}

    VaryDetails(VaryDetails &&) = default;
    VaryDetails &operator=(VaryDetails &&) = default;

    VaryDetails &operator=(const VaryDetails &) = delete;

    VaryDetails clone() const { return VaryDetails(headers_, uuid_); }

    bool operator ==(const VaryDetails &other) const { return uuid_ == other.uuid_ && headers_ == other.headers_; }
    bool operator !=(const VaryDetails &other) const { return !(*this == other); }

    const SBuf &headers() const { return headers_; }
    const RandomUuid &uuid() const { return uuid_; }
    bool isBase() const { return headers_.isEmpty(); }

private:
    VaryDetails(const VaryDetails &other) : headers_(other.headers_), uuid_(other.uuid_.clone()) {}

    /// a vary-mark for leaf entries, may be empty for base/not_cached entries
    SBuf headers_;
    /// vary-based identifier, shared by all leaf entries having the same base entry
    RandomUuid uuid_;
};

std::ostream &operator<<(std::ostream &, const VaryDetails &);

#endif /* SQUID_SRC_BASE_RANDOMUUID_H */

