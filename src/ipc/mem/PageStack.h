/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_PAGE_STACK_H
#define SQUID_IPC_MEM_PAGE_STACK_H

#include "ipc/mem/FlexibleArray.h"

#include <atomic>
#include <limits>

namespace Ipc
{

namespace Mem
{

class PageId;

/// reflects the dual nature of PageStack storage:
/// - for free pages, this is a pointer to the next free page
/// - for used pages, this is a "used page" marker
class PageStackStorageSlot
{
public:
    typedef uint32_t PointerOrMarker;
    typedef PointerOrMarker Pointer;
    typedef PointerOrMarker Marker;

    /// represents a nil next slot pointer
    static const Pointer NilPtr = std::numeric_limits<PointerOrMarker>::max();
    /// marks a slot of a used (i.e. take()n) page
    static const Marker TakenPage = std::numeric_limits<PointerOrMarker>::max() - 1;
    static_assert(TakenPage != NilPtr);

    explicit PageStackStorageSlot(const Pointer next = NilPtr): nextOrMarker(next) {}

    /// returns a (possibly nil) pointer to the next free page
    Pointer next() const { return nextOrMarker.load(); }

    /// marks our page as used
    void take();

    /// marks our page as free, to be used before the given `next` page;
    /// also checks that the slot state matches the caller expectations
    void put(const PointerOrMarker expected, const Pointer next);

private:
    std::atomic<PointerOrMarker> nextOrMarker;
};

/// Atomic container of "free" page numbers inside a single SharedMemory space.
/// Assumptions: all page numbers are unique, positive, have an known maximum,
/// and can be temporary unavailable as long as they are never trully lost.
class PageStack
{
public:
    typedef std::atomic<size_t> Levels_t;

    PageStack(const uint32_t aPoolId, const unsigned int aCapacity, const size_t aPageSize);

    unsigned int capacity() const { return capacity_; }
    size_t pageSize() const { return thePageSize; }
    /// an approximate number of free pages
    unsigned int size() const { return size_.load(); }

    /// sets value and returns true unless no free page numbers are found
    bool pop(PageId &page);
    /// makes value available as a free page number to future pop() callers
    void push(PageId &page);

    bool pageIdIsValid(const PageId &page) const;

    /// total shared memory size required to share
    static size_t SharedMemorySize(const uint32_t aPoolId, const unsigned int capacity, const size_t pageSize);
    size_t sharedMemorySize() const;

    /// shared memory size required only by PageStack, excluding
    /// shared counters and page data
    static size_t StackSize(const unsigned int capacity);
    size_t stackSize() const;

private:
    using Slot = PageStackStorageSlot;

    // XXX: theFoo members look misplaced due to messy separation of PagePool
    // (which should support multiple Segments but does not) and PageStack
    // (which should not calculate the Segment size but does) duties.
    const uint32_t thePoolId; ///< pool ID
    const unsigned int capacity_; ///< the maximum number of pages
    const size_t thePageSize; ///< page size, used to calculate shared memory size

    /// a lower bound for the number of free pages (for debugging purposes)
    std::atomic<unsigned int> size_;

    /// the index of the first free stack element or nil
    std::atomic<Slot::Pointer> head_;

    /// slots indexed using their page number
    Ipc::Mem::FlexibleArray<Slot> slots_;
    // No more data members should follow! See Ipc::Mem::FlexibleArray<> for details.
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_STACK_H

