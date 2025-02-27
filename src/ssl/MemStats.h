/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_MEM_STATS_H
#define SQUID_SRC_SSL_MEM_STATS_H 

#if USE_OPENSSL

#include "StatHist.h"

#include <iosfwd>

class StoreEntry;

namespace Ssl
{

/// Statistics for OpenSSL malloc-based memory management.
class MemStats
{
public:
    MemStats(const char *allocFunName, const char *freeFunName);

    void alloc(size_t bytes);
    void free() { numFrees++; }

    void dumpHistogram(StoreEntry *e);
    void print(std::ostream &os);

    uint64_t numAllocs = 0; ///< the number of malloc() calls
    uint64_t numFrees = 0; ///< the number of free() calls
    uint64_t maxAllocation = 0; ///< the biggest allocated memory block so far (in bytes)

    StatHist allocSizes;
    const char *allocFun = nullptr; ///< the name of an alloc function (e.g., malloc() or realloc())
    const char *freeFun = nullptr; ///< the name of a free() function (or nil)
};

MemStats &MallocStats();
MemStats &ReallocStats();

} // namespace Ssl

#endif // USE_OPENSSL

#endif // SQUID_SRC_SSL_MEM_STATS_H

