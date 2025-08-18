/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_MEMSTATS_H
#define SQUID_SRC_SSL_MEMSTATS_H

#if USE_OPENSSL

#include "StatHist.h"
#include "store/forward.h"

namespace Ssl
{

/// Statistics for OpenSSL malloc-based memory management.

/// malloc() and realloc() statistics
class MemAllocStats
{
public:
    MemAllocStats(const char *desc);

    /// adds a malloc() or realloc() result to the statistics
    void addArea(size_t bytes) { allocSizes.count(bytes); }

    void dump(StoreEntry &);

protected:
    const char *description = nullptr; ///< the allocation function description
    StatHist allocSizes; ///< histogram of allocated memory blocks
};

MemAllocStats &MallocStats();
MemAllocStats &ReallocOldAddrStats();
MemAllocStats &ReallocNewAddrStats();
size_t &FreeStats();

void ReportMemoryStats(StoreEntry &);

} // namespace Ssl

#endif // USE_OPENSSL

#endif /* SQUID_SRC_SSL_MEMSTATS_H */

