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

/// Common statistics for a single memory management function
/// (i.e., malloc(), realloc() or free())
class MemStats
{
public:
    MemStats(const char *fun) : funName(fun) {}
    virtual ~MemStats() {}

    /// adds a call to the statistics
    void addCall() { calls++; }

    virtual void dump(StoreEntry &);

protected:
    uint64_t calls = 0; ///< the total number of calls
    const char *funName = nullptr; ///< the name of a function
};

/// malloc() statistics
class MemAllocStats : public MemStats
{
public:
    MemAllocStats(const char *fun);

    /// adds a malloc() call to the statistics
    void addArea(size_t bytes);

    void dump(StoreEntry &) override;

protected:
    uint64_t maxAllocation = 0; ///< the biggest allocated memory block so far (in bytes)
    StatHist allocSizes; ///< histogram of allocated memory blocks
};

/// realloc() statistics
class MemReallocStats : public MemStats
{
public:
    MemReallocStats(const char *fun);

    /// adds a realloc() call to the statistics which did not
    /// change the memory block location
    void addOldArea(size_t bytes);
    /// adds a realloc() call to the statistics which changed the memory block location
    void addNewArea(size_t bytes);

    virtual void dump(StoreEntry &) override;

protected:
    uint64_t maxReallocationOldArea = 0; ///< the biggest reallocated memory block so far without changing memory location
    uint64_t maxReallocationNewArea = 0; ///< the biggest allocated memory block so far with a new memory location
    StatHist reallocNewAreaSizes; ///< histogram of reallocated memory blocks, having new memory locations
};

MemAllocStats &MallocStats();
MemReallocStats &ReallocStats();
MemStats &FreeStats();

void ReportMemoryStats(StoreEntry &);

} // namespace Ssl

#endif // USE_OPENSSL

#endif /* SQUID_SRC_SSL_MEMSTATS_H */

