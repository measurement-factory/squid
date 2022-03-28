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

static_assert(sizeof(RandomUuid) == 16, "RandomUuid expected size");

RandomUuid::RandomUuid()
{
    using ResultType = std::mt19937_64::result_type;
    const auto ResultSize = sizeof(ResultType);
    static std::random_device dev;
    static std::mt19937_64 gen(dev());
    const auto low = gen();
    const auto high = gen();

    static_assert(2*sizeof(ResultType) == sizeof(RandomUuid), "RandomUuid expected size for generator");
    memcpy(reinterpret_cast<char *>(this), &low, ResultSize);
    memcpy(reinterpret_cast<char *>(this) + ResultSize, &high, ResultSize);

    // RFC4122 section 4.4
    EBIT_CLR(clockSeqHiAndReserved, 6);
    EBIT_SET(clockSeqHiAndReserved, 7);
    // section 4.1.3 variant 4 
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

