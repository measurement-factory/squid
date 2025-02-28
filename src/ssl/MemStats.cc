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

Ssl::MemStats::MemStats(const char *allocFunName, const char *freeFunName)
    : allocFun(allocFunName), freeFun(freeFunName)
{
    allocSizes.logInit(20, 0, 1024*1024);
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
Ssl::MemStats::dump(StoreEntry &e)
{
    PackableStream yaml(e);
    assert(allocFun);
    yaml << allocFun << "() calls: " <<  numAllocs << "\n";
    yaml << allocFun << "() single call bytes allocated (max): " << maxAllocation << "\n";
    if (freeFun)
        yaml << freeFun << "() calls: " <<  numFrees << "\n";
    yaml << allocFun << "() sizes histogram:" << "\n";
    yaml.flush();
    allocSizes.dump(&e, nullptr);
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

