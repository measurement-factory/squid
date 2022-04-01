/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "base/Raw.h"
#include "defines.h"
#include "RandomUuid.h"

#include <iomanip>
#include <random>

static_assert(sizeof(RandomUuid) == 16, "RandomUuid has RFC 4122-prescribed size");

RandomUuid::RandomUuid()
{
    // generate random bits for populating UUID
    using ResultType = std::mt19937_64::result_type;
    const auto ResultSize = sizeof(ResultType);
    static std::random_device dev;
    static std::mt19937_64 gen(dev());
    const auto low = gen();
    const auto high = gen();

    // bullet 3 of RFC 4122 Section 4.4 algorithm but setting all bits (KISS)
    static_assert(2*sizeof(ResultType) == sizeof(RandomUuid), "enough randomness bits to fill a UUID");
    memcpy(reinterpret_cast<char *>(this), &low, ResultSize);
    memcpy(reinterpret_cast<char *>(this) + ResultSize, &high, ResultSize);

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
    os << Raw("UUID", reinterpret_cast<const char *>(this), sizeof(RandomUuid)).hex();
}

RandomUuid
RandomUuid::clone() const
{
    RandomUuid uuid;
    memcpy(reinterpret_cast<char *>(&uuid), reinterpret_cast<const char *>(this), sizeof(RandomUuid));
    return uuid;
}

void
RandomUuid::load(const void *data, const size_t length)
{
    assert(length == sizeof(RandomUuid));
    memcpy(reinterpret_cast<char *>(this), data, sizeof(RandomUuid));
}

bool
RandomUuid::operator ==(const RandomUuid &other) const
{
    return memcmp(this, &other, sizeof(RandomUuid)) == 0;
}

