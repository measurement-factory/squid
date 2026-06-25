/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FS_ROCK_ROCKSWAPDIR_H
#define SQUID_SRC_FS_ROCK_ROCKSWAPDIR_H

#include "base/OnOff.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"
#include "fs/rock/forward.h"
#include "fs/rock/RockDbCell.h"
#include "fs/rock/RockRebuild.h"
#include "Instance.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "sbuf/forward.h"
#include "store/Disk.h"
#include "store_rebuild.h"

#include <memory>
#include <optional>
#include <vector>

class DiskIOStrategy;
class ReadRequest;
class WriteRequest;

namespace Rock
{

/// \ingroup Rock
class SwapDir: public ::SwapDir, public IORequestor, public Ipc::StoreMapCleaner
{
public:
    typedef RefCount<SwapDir> Pointer;
    typedef Ipc::StoreMap DirMap;

    SwapDir();
    ~SwapDir() override;

    /// Synchronously reacts to this process imminent termination. May be slow.
    /// This method exists (i.e. we do not rely on the destructor) because
    /// reference counting makes this object destruction _timing_ unpredictable
    /// and may violate this method preconditions:
    /// \prec Disk I/O modules are still fully functional.
    /// \prec All transaction caching activity has ended before this call.
    void shutdown();

    /* public ::SwapDir API */
    void reconfigure() override;
    StoreEntry *get(const cache_key *key) override;
    void evictCached(StoreEntry &) override;
    void evictIfFound(const cache_key *) override;
    void disconnect(StoreEntry &e) override;
    uint64_t currentSize() const override;
    uint64_t currentCount() const override;
    bool doReportStat() const override;
    void finalizeSwapoutSuccess(const StoreEntry &) override;
    void finalizeSwapoutFailure(StoreEntry &) override;
    void create() override;
    void parse(int index, char *path) override;
    bool smpAware() const override { return true; }
    bool hasReadableEntry(const StoreEntry &) const override;

    // temporary path to the shared memory map of first slots of cached entries
    SBuf inodeMapPath() const;

    int64_t entryLimitAbsolute() const { return SwapFilenMax+1; } ///< Core limit
    int64_t entryLimitActual() const; ///< max number of possible entries in db
    int64_t slotLimitAbsolute() const; ///< Rock store implementation limit
    int64_t slotLimitActual() const; ///< total number of slots in this db

    /// whether the given slot ID may point to a slot in this db
    bool validSlotId(const SlotId slotId) const;

    /// finds and returns a free db slot to fill or throws
    SlotId reserveSlotForWriting();

    /// purges one or more entries to make full() false and free some slots
    void purgeSome();

    int64_t diskOffset(Ipc::Mem::PageId &pageId) const;
    int64_t diskOffset(SlotId) const;
    void writeError(StoreIOState &sio);

    /* StoreMapCleaner API */
    void noteFreeMapSlice(Ipc::StoreMapSliceId, bool) override;
    void noteFreeMapInodeCandidate(sfileno) override;

    uint64_t slotSize; ///< all db slots are of this size

protected:
    /* Store API */
    bool anchorToCache(StoreEntry &) override;
    bool updateAnchored(StoreEntry &) override;

    /* protected ::SwapDir API */
    bool needsDiskStrand() const override;
    void init() override;
    ConfigOption *getOptionTree() const override;
    bool allowOptionReconfigure(const char *const option) const override;
    bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const override;
    StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    void maintain() override;
    void diskFull() override;
    void reference(StoreEntry &e) override;
    bool dereference(StoreEntry &e) override;
    void updateHeaders(StoreEntry *e) override;
    bool unlinkdUseful() const override;
    void statfs(StoreEntry &e) const override;

    /* IORequestor API */
    void ioCompletedNotification() override;
    void closeCompleted() override;
    void readCompleted(const char *buf, int len, int errflag, RefCount< ::ReadRequest>) override;
    void writeCompleted(int errflag, size_t len, RefCount< ::WriteRequest>) override;

    void parseSize(const bool reconfiguring); ///< parses anonymous cache_dir size option
    void validateOptions(); ///< warns of configuration problems; may quit
    bool parseTimeOption(char const *option, const char *value, int reconfiguring);
    void dumpTimeOption(StoreEntry * e) const;
    bool parseRateOption(char const *option, const char *value, int reconfiguring);
    void dumpRateOption(StoreEntry * e) const;
    bool parseSizeOption(char const *option, const char *value, int reconfiguring);
    void dumpSizeOption(StoreEntry * e) const;

    bool full() const; ///< no more entries can be stored without purging
    void trackReferences(StoreEntry &e); ///< add to replacement policy scope
    void ignoreReferences(StoreEntry &e); ///< delete from repl policy scope

    int64_t diskOffsetLimit() const;

    void updateHeadersOrThrow(Ipc::StoreMapUpdate &update);
    StoreIOState::Pointer createUpdateIO(const Ipc::StoreMapUpdate &, StoreIOState::STIOCB *, void *);

    void anchorEntry(StoreEntry &e, const sfileno filen, const Ipc::StoreMapAnchor &anchor);

    friend class Rebuild;
    friend class IoState;
    friend class HeaderUpdater;
    const char *filePath; ///< location of cache storage file inside path/
    DirMap *map; ///< entry key/sfileno to MaxExtras/inode mapping

private:
    void createError(const char *const msg);
    void handleWriteCompletionSuccess(const WriteRequest &request);
    void handleWriteCompletionProblem(const int errflag, const WriteRequest &request);
    void zeroMarkedForDeletion();

    /// tracks (often asynchronous) opening of theFile
    Instance::OptionalStartupActivityTracker startupTracker;

    DiskIOStrategy *io;
    RefCount<DiskFile> theFile; ///< cache storage for this cache_dir
    std::unique_ptr<FreeSlots> freeSlots; ///< all unused slots
    Ipc::Mem::PageId *waitingForPage; ///< one-page cache for a "hot" free slot

    /* configurable options */
    DiskFile::Config fileConfig; ///< file-level configuration options

    static const int64_t HeaderSize = 16*1024; ///< on-disk db header size
};

/// Whether to zero a db cell header on disk. To reduce disk writes in busy
/// environments where most freed db slots become used again, Rock delays
/// zeroing until SwapDir::shutdown(). To reduce zeroing costs at shutdown, Rock
/// classifies slots (at slot freeing time; as detailed below) and then only
/// zeroes (at shutdown) those slots that were classified as needing zeroing.
///
/// * ZeroWhenFlushing:on slots are slots that require zeroing: If left intact,
///   they may be treated as valid Store entries during the next Squid startup,
///   leading to, for example, cache hits for resources purged by the previous
///   Squid instance. Zeroing prevents entry "resurrections" and other problems.
///
/// * ZeroWhenFlushing:off slots are slots that do not require zeroing.
///
/// \sa Rock::ZeroingRequest
using ZeroWhenFlushing = OnOff;

/// Whether the associated item has already been freed.
///
/// * DelayedFreeing:off items are available for reuse now.
///
/// * DelayedFreeing:on items are cache_dir inodes that are marked for deletion
///   but not yet available for reuse (e.g., because they are still locked by a
///   cache reader). They are expected to become reusable, usually fairly soon
///   (e.g., when the transaction reading the cache entry ends).
///
/// \sa ZeroWhenFlushing
using DelayedFreeing = OnOff;

/// Slot IDs of currently unused db cells inside one rock cache_dir.
/// Also maintains an index of entries that are waiting to be freed (i.e. become unused).
class FreeSlots
{
public:
    using PageCount = Ipc::Mem::PageStack::PageCount;
    using PageId = Ipc::Mem::PageId;

    /// Ipc::Mem::PageStack creation instructions.
    class Config: public Ipc::Mem::PageStack::Config
    {
    public:
        Config(const SwapDir::Pointer &, ZeroWhenFlushing, DelayedFreeing);

        /// the name of Ipc::Mem::Segment that contains our free slot IDs
        SBuf segmentName() const;

        /// cache_dir that contains our free slots
        Rock::SwapDir::Pointer swapDir;

        /// classifies free slots in the being-configured Ipc::Mem::PageStack
        ZeroWhenFlushing zeroWhenFlushing;

        /// classifies free slots in the being-configured Ipc::Mem::PageStack
        DelayedFreeing delayedFreeing;
    };

    explicit FreeSlots(const SwapDir::Pointer &);

    /// \copydoc Ipc::Mem::PageStack::size()
    PageCount size() const;

    /// either extracts a previously pushed slot, sets the given PageId, and
    /// returns true (if a free slot was available) or returns false (otherwise)
    bool pop(PageId &);

    /// Like pop() but only extracts ZeroWhenFlushing:on slots.
    /// This method is only meant to be used during cache_dir flushing.
    /// \sa ZeroWhenFlushing
    bool popToBeZeroed(PageId &pageId) { return slotsToBeZeroed->pop(pageId); }

    /// makes the given page available to a future pop() caller
    void push(PageId &pageId, const ZeroWhenFlushing zeroWhenFlushing) { !zeroWhenFlushing ? slotsToBeLeftAsIs->push(pageId) : slotsToBeZeroed->push(pageId); }

    void noteCandidate(PageId &pageId) { candidates->push(pageId); }

private:
    Ipc::Mem::Pointer<Ipc::Mem::PageStack> slotsToBeZeroed; ///< free ZeroWhenFlushing::on slots
    Ipc::Mem::Pointer<Ipc::Mem::PageStack> slotsToBeLeftAsIs; ///< free ZeroWhenFlushing::off slots
    Ipc::Mem::Pointer<Ipc::Mem::PageStack> candidates; ///< future free slots (DelayedFreeing:on)
};

/// initializes shared memory segments used by Rock::SwapDir
class SwapDirRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* ::RegisteredRunner API */
    ~SwapDirRr() override;

protected:
    /* Ipc::Mem::RegisteredRunner API */
    void create() override;
    void endingShutdown() override;

private:
    std::vector<Ipc::Mem::Owner<Rebuild::Stats> *> rebuildStatsOwners;
    std::vector<SwapDir::DirMap::Owner *> mapOwners;
    std::vector< Ipc::Mem::Owner<Ipc::Mem::PageStack> *> freeSlotsOwners;
};

} // namespace Rock

#endif /* SQUID_SRC_FS_ROCK_ROCKSWAPDIR_H */

