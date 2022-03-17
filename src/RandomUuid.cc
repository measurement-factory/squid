/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "defines.h"
#include "RandomUuid.h"

#include <chrono>
#include <iomanip>
#include <random>

RandomUuid::RandomUuid()
{
    using ResultType = std::mt19937_64::result_type;
    const auto ResultSize = sizeof(ResultType);
    static_assert(2*sizeof(ResultType) == sizeof(RandomUuid), "RandomUuid expected size");
    const auto seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::mt19937_64 gen(seed);
    const auto low = gen();
    const auto high = gen();
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

RandomUuid::RandomUuid(void *data, const int length)
{
    assert(length == sizeof(RandomUuid));
    memcpy(reinterpret_cast<char *>(this), data, sizeof(RandomUuid));
}

void
RandomUuid::print(std::ostream &os)
{
    std::cout << "0x" << std::setfill('0') << std::hex << std::setw(16) <<
        reinterpret_cast<uint64_t>(this+64) << reinterpret_cast<uint64_t>(this);
}

bool
RandomUuid::operator ==(const RandomUuid &other)
{
    return memcmp(this, &other, sizeof(RandomUuid)) == 0;
}

