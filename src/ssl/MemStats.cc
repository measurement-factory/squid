/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/PackableStream.h"
#include "ssl/MemStats.h"

#if USE_OPENSSL

Ssl::MemAllocStats::MemAllocStats(const char * const aDescription):
    description(aDescription)
{
    allocations.logInit(20, 0, 1024*1024);
}

/// a [compile-time] string containing exactly N spaces
template <size_t N>
constexpr auto
spaces()
{
    constexpr auto maximumSpace = "                                          ";

    // we use a constexpr variant of strlen() to check whether N is small enough
    constexpr auto maximumLength = std::char_traits<char>::length(maximumSpace);
    static_assert(N <= maximumLength);

    return maximumSpace + maximumLength - N;
}

/// Supplies one level of YAML indentation. Keep in sync with AsyncJob::ReportAllJobs().
template <size_t L = 1> constexpr auto yamlIndent() { return spaces<4*L>(); }

/// YAML-compliant StatHistBinDumper for memory allocation stats
static void
BinToYamlListItem(StoreEntry * const e, int, const double minValue, const double bucketSize, const int valueCount)
{
    if (!valueCount)
        return;

    PackableStream yaml(*e);
    // our allocations.logInit() limits sizes to 7 digits; valueCount may have 10
    const auto setw = [](std::ostream &os) -> auto& { return os << std::setw(10); };
    yaml << yamlIndent() << yamlIndent() << yamlIndent() << "- { " <<
         "min: " << setw << static_cast<uint64_t>(minValue) << ", " <<
         "max: " << setw << (static_cast<uint64_t>(minValue+bucketSize)-1) << ", " <<
         "count: " << setw << valueCount << " }\n";
}

void
Ssl::MemAllocStats::dump(StoreEntry &e)
{
    PackableStream yaml(e);
    yaml << yamlIndent() << "stats for " << description << ":\n";
    yaml << yamlIndent() << yamlIndent() << "calls: " << allocations.valuesCounted() << "\n";
    if (allocations.valuesCounted())
        yaml << yamlIndent() << yamlIndent() << "allocation size histogram (bytes):" << "\n";
    yaml.flush();
    allocations.dump(&e, &BinToYamlListItem);
}

Ssl::MemAllocStats &
Ssl::MallocStats()
{
    static const auto stats = new MemAllocStats("malloc()");
    return *stats;
}

Ssl::MemAllocStats &
Ssl::ReallocOldAddrStats()
{
    static const auto stats = new MemAllocStats("realloc() that preserved address");
    return *stats;
}

Ssl::MemAllocStats &
Ssl::ReallocNewAddrStats()
{
    static const auto stats = new MemAllocStats("realloc() that changed address");
    return *stats;
}

uint64_t &
Ssl::FreeStats()
{
    static uint64_t callsCounter = 0;
    return callsCounter;
}

void
Ssl::ReportMemoryStats(StoreEntry &e)
{
    PackableStream yaml(e);

    yaml << "OpenSSL memory usage:\n";

    // re-allocations (e.g., ReallocNewAddrStats()) do not change the number of allocations in use
    const auto allocated = MallocStats().allocationsCounted();
    const auto freed = FreeStats();
    if (allocated >= freed)
        yaml << yamlIndent() << "in-use allocations: " << (allocated - freed) << "\n";

    // match MallocStats() reporting style even though we cannot report a histogram
    yaml << yamlIndent() << "stats for free():" << "\n";
    yaml << yamlIndent() << yamlIndent() << "calls: " << freed << "\n";

    yaml.flush();

    MallocStats().dump(e);
    ReallocOldAddrStats().dump(e);
    ReallocNewAddrStats().dump(e);
}

#endif // USE_OPENSSL

