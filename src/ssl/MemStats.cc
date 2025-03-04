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

void
Ssl::MemStats::dump(StoreEntry &e)
{
    PackableStream yaml(e);
    const char *indent = "  ";
    yaml << indent << funName << "() stats:" << "\n";
    yaml << indent << indent << "Calls: " << calls << "\n";
}

Ssl::MemAllocStats::MemAllocStats(const char * const fun):
    MemStats(fun)
{
    allocSizes.logInit(20, 0, 1024*1024);
}

void
Ssl::MemAllocStats::addArea(const size_t bytes)
{
    MemStats::addCall();
    if (bytes > maxAllocation)
        maxAllocation = bytes;
    allocSizes.count(bytes);
}

void
Ssl::MemAllocStats::dump(StoreEntry &e)
{
    MemStats::dump(e);
    PackableStream yaml(e);
    const char *indent = "  ";
    yaml << indent << indent << "Single call bytes allocated (max): " << maxAllocation << "\n";
    yaml << indent << indent << "Allocations histogram (bytes):" << "\n";
    yaml.flush();
    allocSizes.dump(&e, nullptr);
}

Ssl::MemReallocStats::MemReallocStats(const char * const fun):
    MemStats(fun)
{
    reallocNewAreaSizes.logInit(20, 0, 1024*1024);
}

void
Ssl::MemReallocStats::addOldArea(const size_t bytes)
{
    MemStats::addCall();
    if (bytes > maxReallocationOldArea)
        maxReallocationOldArea = bytes;
}

void
Ssl::MemReallocStats::addNewArea(const size_t bytes)
{
    MemStats::addCall();
    if (bytes > maxReallocationNewArea)
        maxReallocationNewArea = bytes;
    reallocNewAreaSizes.count(bytes);
}

void
Ssl::MemReallocStats::dump(StoreEntry &e)
{
    MemStats::dump(e);
    PackableStream yaml(e);
    const char *indent = "  ";
    yaml << indent << indent << "Single call bytes reallocated (max) (old memory location): " << maxReallocationOldArea << "\n";
    yaml << indent << indent << "Single call bytes reallocated (max) (new memory location): " << maxReallocationNewArea << "\n";
    yaml << indent << indent << "Reallocations histogram (new base address, bytes):" << "\n";
    yaml.flush();
    reallocNewAreaSizes.dump(&e, nullptr);
}

Ssl::MemAllocStats &
Ssl::MallocStats()
{
    static auto stats = new MemAllocStats("malloc");
    return *stats;
}

Ssl::MemReallocStats &
Ssl::ReallocStats()
{
    static auto stats = new MemReallocStats("realloc");
    return *stats;
}

Ssl::MemStats &
Ssl::FreeStats()
{
    static auto stats = new MemStats("free");
    return *stats;
}

void
Ssl::ReportMemoryStats(StoreEntry &e)
{
    PackableStream yaml(e);
    yaml << "Current SSL memory usage:\n";
    yaml.flush();
    MallocStats().dump(e);
    ReallocStats().dump(e);
    FreeStats().dump(e);
}

#endif // USE_OPENSSL

