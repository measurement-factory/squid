/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
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

/// OpenSSL memory (re)allocation statistics
class MemAllocStats
{
public:
    explicit MemAllocStats(const char *aDescription);

    /// records a (re)allocation of a buffer that can accommodate the given
    /// number of bytes
    void addArea(size_t bytes) { allocSizes.count(bytes); }

    /// reports collected stats using YAML format
    void dump(StoreEntry &);

private:
    /// describes the allocation function being tracked (for dump())
    const char *description;

    /// histogram of addArea() parameter values
    StatHist allocSizes;
};

/// CRYPTO_malloc(3) call stats
MemAllocStats &MallocStats();
/// CRYPTO_realloc(3) call stats for cases where the old buffer address was preserved
MemAllocStats &ReallocOldAddrStats();
/// CRYPTO_realloc(3) call stats for cases where a buffer was allocated at a new address
MemAllocStats &ReallocNewAddrStats();
/// the number of CRYPTO_free() calls made so far
uint64_t &FreeStats();

/// Dumps current memory statistics for CRYPTO_malloc/realloc/free(3) calls using YAML format.
void ReportMemoryStats(StoreEntry &);

} // namespace Ssl

#endif // USE_OPENSSL

#endif /* SQUID_SRC_SSL_MEMSTATS_H */

