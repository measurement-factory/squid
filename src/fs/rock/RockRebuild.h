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
#include "base/RunnersRegistry.h"
#include "cbdata.h"
#include "fs/rock/forward.h"
#include "ipc/mem/Pointer.h"
#include "ipc/StoreMap.h"
#include "MemBuf.h"
#include "store_rebuild.h"

namespace Rock
{

class LoadingEntry;
class LoadingSlot;
class LoadingPartsOwner;

/// \ingroup Rock
/// manages store rebuild process: loading meta information from db on disk
class Rebuild: public AsyncJob, private IndependentRunner
{
    CBDATA_CHILD(Rebuild);

public:
    /// shared metadata during rebuild process
    class Metadata
    {
    public:
        size_t sharedMemorySize() const { return sizeof(*this); }
        static size_t SharedMemorySize() { return sizeof(Metadata); }
        static SBuf Path(const char *dirPath);
        /// whether the rebuild is finished already
        bool completed(const SwapDir *) const;

        StoreRebuildData counts;
    };

    Rebuild(SwapDir *dir, const Ipc::Mem::Pointer<Metadata> &);
    virtual ~Rebuild() override;

    static Ipc::Mem::Owner<Metadata> *InitMetadata(const SwapDir *dir);

    /// whether the current kid is responsible for rebuilding this db file
    static bool IsResponsible(const SwapDir &);

    /* Registered Runner API */
    virtual void startShutdown() override;

protected:
    /* AsyncJob API */
    virtual void start() override;
    virtual bool doneAll() const override;
    virtual void swanSong() override;

    bool loadedAndValidated() const { return doneLoading() && doneValidating(); }
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

    SBuf progressDescription() const;

    SwapDir *sd;

    Ipc::Mem::Pointer<Metadata> metadata; ///< shared metadata

    int64_t dbSize;
    int dbSlotSize; ///< the size of a db cell, including the cell header
    int dbSlotLimit; ///< total number of db cells
    int dbEntryLimit; ///< maximum number of entries that can be stored in db

    int fd; // store db file descriptor
    int64_t dbOffset; // TODO: calculate in a method, using loadingPos
    sfileno loadingPos; ///< index of the db slot being loaded from disk now
    sfileno validationPos; ///< index of the loaded db slot being validated now
    MemBuf buf; ///< space to load current db slot (and entry metadata) into

    StoreRebuildData &counts; ///< a reference to the shared memory counters
    /// shared memory storage where parts of being loaded entries are
    /// temporarily stored
    LoadingPartsOwner *partsOwner;
    /// whether the rebuild process was aborted and now resumed
    const bool resuming;

    static void Steps(void *data);
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_REBUILD_H */

