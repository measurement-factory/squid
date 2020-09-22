/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#ifndef SQUID_STORE_REBUILD_H_
#define SQUID_STORE_REBUILD_H_

#include "store_key_md5.h"

class MemBuf;

class StoreRebuildData
{
public:
    void updateStartTime(const timeval &newTime) { startTime = started() ? std::min(startTime, newTime) : newTime; }

    bool started() const { return startTime.tv_sec > 0; }

    int objcount = 0;       /* # objects successfully reloaded */
    int expcount = 0;       /* # objects expired */
    int scancount = 0;      /* # entries scanned or read from state file */
    int clashcount = 0;     /* # swapfile clashes avoided */
    int dupcount = 0;       /* # duplicates purged */
    int cancelcount = 0;    /* # SWAP_LOG_DEL objects purged */
    int invalid = 0;        /* # bad lines */
    int badflags = 0;       /* # bad e->flags */
    int bad_log_op = 0;
    int zero_object_sz = 0;
    int validatedCount = 0; ///< the number of validated entries
    timeval startTime = {}; ///< when the rebuild has started
};

/// prints the progress of an operation
class ProgressDescription
{
public:
    ProgressDescription(const char *label, const int count, const int total):
        label_(label), count_(count), total_(total) {}

    std::ostream &print(std::ostream &os) const;

private:
    const char *label_;
    const int count_;
    const int total_;
};

inline
std::ostream &operator <<(std::ostream &os, const ProgressDescription &p)
{
    return p.print(os);
}

void storeRebuildStart(void);
void storeRebuildComplete(StoreRebuildData *);
/// starts a directory tracking as being built
void storeRebuildRegister();
/// stops a directory tracking as being built
bool storeRebuildUnregister();
void storeRebuildProgress(int sd_index, int total, int sofar);

/// loads entry from disk; fills supplied memory buffer on success
bool storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf, StoreRebuildData &counts);
/// parses entry buffer and validates entry metadata; fills e on success
bool storeRebuildParseEntry(MemBuf &buf, StoreEntry &e, cache_key *key, StoreRebuildData &counts, uint64_t expectedSize);

#endif /* SQUID_STORE_REBUILD_H_ */

