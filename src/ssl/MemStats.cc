/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "base/PackableStream.h"
#include "ssl/MemStats.h"

#if USE_OPENSSL

Ssl::MemAllocStats::MemAllocStats(const char * const desc):
    description(desc)
{
    allocSizes.logInit(20, 0, 1024*1024);
}

void
Ssl::MemAllocStats::dump(StoreEntry &e)
{
    PackableStream yaml(e);
    const char *indent = "  ";
    yaml << indent << description << " stats:" << "\n";
    yaml << indent << indent << "Calls: " << allocSizes.size() << "\n";
    yaml << indent << indent << "Allocations histogram (bytes):" << "\n";
    yaml.flush();
    allocSizes.dump(&e, nullptr);
}

Ssl::MemAllocStats &
Ssl::MallocStats()
{
    static auto stats = new MemAllocStats("malloc()");
    return *stats;
}

Ssl::MemAllocStats &
Ssl::ReallocOldAddrStats()
{
    static auto stats = new MemAllocStats("realloc(), old base address");
    return *stats;
}

Ssl::MemAllocStats &
Ssl::ReallocNewAddrStats()
{
    static auto stats = new MemAllocStats("realloc(), new base address");
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
    const char *indent = "  ";
    yaml << "Current SSL memory usage:\n";
    yaml << indent << "free() stats:" << "\n";
    yaml << indent << indent << "Calls: " << FreeStats() << "\n";
    yaml.flush();
    MallocStats().dump(e);
    ReallocOldAddrStats().dump(e);
    ReallocNewAddrStats().dump(e);
}

#endif // USE_OPENSSL

