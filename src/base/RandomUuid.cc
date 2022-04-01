/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "base/RandomUuid.h"
#include "base/Raw.h"
#include "defines.h"

#include <iostream>
#include <random>

static_assert(sizeof(RandomUuid) == 128/8, "RandomUuid has RFC 4122-prescribed 128-bit size");

RandomUuid::RandomUuid()
{
    // Generate random bits for populating our UUID.
    // STL implementation bugs notwithstanding (e.g., MinGW bug #338), this is
    // our best change of getting a non-deterministic seed value for the r.n.g.
    static std::random_device dev; // unknown a priori size (sizeof(int)) values
    static std::mt19937_64 rng(dev()); // known 64-bit size values
    const auto rnd1 = rng();
    const auto rnd2 = rng();

    // bullet 3 of RFC 4122 Section 4.4 algorithm but setting all bits (KISS)
    static_assert(sizeof(rnd1) + sizeof(rnd2) == sizeof(*this), "random bits fill a UUID");
    memcpy(raw(), &rnd1, sizeof(rnd1));
    memcpy(raw() + sizeof(rnd1), &rnd2, sizeof(rnd2));

    // bullet 1 of RFC 4122 Section 4.4 algorithm
    EBIT_CLR(clockSeqHiAndReserved, 6);
    EBIT_SET(clockSeqHiAndReserved, 7);

    // bullet 2 of RFC 4122 Section 4.4 algorithm
    EBIT_CLR(timeHiAndVersion, 13);
    EBIT_SET(timeHiAndVersion, 14);
    EBIT_CLR(timeHiAndVersion, 15);
    EBIT_CLR(timeHiAndVersion, 16);
}

void
RandomUuid::print(std::ostream &os) const
{
    os << Raw("UUID", raw(), sizeof(*this)).hex();
}

RandomUuid
RandomUuid::clone() const
{
    RandomUuid uuid;
    memcpy(uuid.raw(), raw(), sizeof(uuid));
    return uuid;
}

void
RandomUuid::load(const void *data, const size_t length)
{
    assert(length == sizeof(*this));
    memcpy(raw(), data, sizeof(*this));
}

bool
RandomUuid::operator ==(const RandomUuid &other) const
{
    return memcmp(raw(), other.raw(), sizeof(*this)) == 0;
}

