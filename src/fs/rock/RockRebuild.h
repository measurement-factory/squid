/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_REBUILD_H
#define SQUID_FS_ROCK_REBUILD_H

#include "base/AsyncJob.h"
#include "cbdata.h"
#include "fs/rock/forward.h"
#include "MemBuf.h"
#include "store_rebuild.h"

namespace Rock
{

class LoadingEntry;
class LoadingSlot;
class LoadingParts;

/// \ingroup Rock
/// manages store rebuild process: loading meta information from db on disk
class Rebuild: public AsyncJob
{
    CBDATA_CHILD(Rebuild);

public:
    Rebuild(SwapDir *dir);
    virtual ~Rebuild() override;

protected:
    /* AsyncJob API */
    virtual void start() override;
    virtual bool doneAll() const override;
    virtual void swanSong() override;

    bool doneLoading() const;
    bool doneValidating() const;

private:
    void checkpoint();
    void steps();
    void loadingSteps();
    void validationSteps();
    void loadOneSlot();
    void validateOneEntry(const sfileno fileNo);
    void validateOneSlot(const SlotId slotId);
    bool importEntry(Ipc::StoreMapAnchor &anchor, const sfileno slotId, const DbCellHeader &header);
    void freeBadEntry(const sfileno fileno, const char *eDescription);

    void failure(const char *msg, int errNo = 0);

    LoadingEntry loadingEntry(const sfileno fileNo);
    void startNewEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header);
    void primeNewEntry(Ipc::StoreMapAnchor &anchor, const sfileno fileno, const DbCellHeader &header);
    void finalizeOrFree(const sfileno fileNo, LoadingEntry &le);
    void finalizeOrThrow(const sfileno fileNo, LoadingEntry &le);
    void addSlotToEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header);
    void useNewSlot(const SlotId slotId, const DbCellHeader &header);

    LoadingSlot loadingSlot(const SlotId slotId);
    void mapSlot(const SlotId slotId, const DbCellHeader &header);
    void freeUnusedSlot(const SlotId slotId, const bool invalid);
    void freeSlot(const SlotId slotId, const bool invalid);

    template <class SlotIdType>
    void chainSlots(SlotIdType &from, const SlotId to);

    bool sameEntry(const sfileno fileno, const DbCellHeader &header) const;

    SwapDir *sd;
    LoadingParts *parts; ///< parts of store entries being loaded from disk

    int64_t dbSize;
    int dbSlotSize; ///< the size of a db cell, including the cell header
    int dbSlotLimit; ///< total number of db cells
    int dbEntryLimit; ///< maximum number of entries that can be stored in db

    int fd; // store db file descriptor
    int64_t dbOffset;
    sfileno loadingPos; ///< index of the db slot being loaded from disk now
    sfileno validationPos; ///< index of the loaded db slot being validated now
    MemBuf buf; ///< space to load current db slot (and entry metadata) into

    // Balance our desire to maximize the number of entries processed at once
    // (and, hence, minimize overheads and total rebuild time) with a
    // requirement to also process Coordinator events, disk I/Os, etc.
    static const int MaxSpentMsec = 50; // keep small: most RAM I/Os are under 1ms
    static const int ForegroundNotificationMsec = 1000; ///< time interval to react to signals if opt_foreground_rebuild

    StoreRebuildData counts;

    static void Steps(void *data);
    /// sends a notification to Coordinator that the foreground rebuild
    /// is still in progress
    void notifyCoordinator();
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_REBUILD_H */

