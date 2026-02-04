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

void
Ssl::MemAllocStats::dump(StoreEntry &e)
{
    PackableStream yaml(e);
    const auto indent = "  ";
    yaml << indent << "stats for " << description << ":\n";
    yaml << indent << indent << "calls: " << allocations.valuesCounted() << "\n";
    if (allocations.valuesCounted())
        yaml << indent << indent << "allocation size histogram (bytes):" << "\n";
    yaml.flush();
    allocations.dump(&e, nullptr);
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
    const auto indent = "  ";

    yaml << "OpenSSL memory usage:\n";

    // re-allocations (e.g., ReallocNewAddrStats()) do not change the number of allocations in use
    const auto allocated = MallocStats().allocationsCounted();
    const auto freed = FreeStats();
    if (allocated >= freed)
        yaml << indent << "in-use allocations: " << (allocated - freed) << "\n";

    // match MallocStats() reporting style even though we cannot report a histogram
    yaml << indent << "stats for free():" << "\n";
    yaml << indent << indent << "calls: " << freed << "\n";

    yaml.flush();

    MallocStats().dump(e);
    ReallocOldAddrStats().dump(e);
    ReallocNewAddrStats().dump(e);
}

#endif // USE_OPENSSL

