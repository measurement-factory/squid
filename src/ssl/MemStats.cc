/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "ssl/MemStats.h"

#if USE_OPENSSL

Ssl::MemStats::MemStats(const char *allocFunName, const char *freeFunName)
: allocFun(allocFunName), freeFun(freeFunName)
{
    allocSizes.logInit(20, 1., 1048576.);
}

void
Ssl::MemStats::alloc(const size_t bytes)
{
    numAllocs++;
    if (bytes > maxAllocation)
        maxAllocation = bytes;
    allocSizes.count(bytes);
}

void
Ssl::MemStats::print(std::ostream &os)
{
    assert(allocFun);
    os << allocFun << "() calls: " <<  numAllocs << ", the biggest allocation so far: " << maxAllocation << " bytes" <<"\n";
	if (freeFun)
        os << freeFun << "() calls: " <<  numFrees << "\n";
}

void
Ssl::MemStats::dumpHistogram(StoreEntry *e)
{
    storeAppendPrintf(e, "%s() sizes histogram: \n", allocFun);
    allocSizes.dump(e, nullptr);
}

Ssl::MemStats &
Ssl::MallocStats()
{
    static auto stats = new MemStats("malloc", "free");
    return *stats;
}

Ssl::MemStats &
Ssl::ReallocStats()
{
    static auto stats = new MemStats("realloc", nullptr);
    return *stats;
}

#endif // USE_OPENSSL

