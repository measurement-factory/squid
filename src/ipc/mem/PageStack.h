/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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

/// Atomic container of "free" page numbers inside a single SharedMemory space.
/// Assumptions: all page numbers are unique, positive, have an known maximum,
/// and can be temporary unavailable as long as they are never trully lost.
class PageStack
{
public:
    typedef uint32_t Value; ///< stack item type (a free page number)
    typedef std::atomic<size_t> Levels_t;
    const Value NilItem = std::numeric_limits<Value>::max(); ///< 'nil' reference for the first stack item
    const Value NoItem = std::numeric_limits<Value>::max() - 1; ///< 'empty' reference for a popped item

    PageStack(const uint32_t aPoolId, const unsigned int aCapacity, const size_t aPageSize);

    unsigned int capacity() const { return theCapacity; }
    size_t pageSize() const { return thePageSize; }
    /// the number of free pages
    unsigned int size() const { return theSize.load(); }

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

    /// \returns the number of padding bytes to align PagePool::theLevels array
    static size_t LevelsPaddingSize(const unsigned int capacity);
    size_t levelsPaddingSize() const { return LevelsPaddingSize(theCapacity); }

private:

    const uint32_t thePoolId; ///< pool ID
    const Value theCapacity; ///< stack capacity, i.e. theItems size
    const size_t thePageSize; ///< page size, used to calculate shared memory size

    typedef std::atomic<Value> Item;
    Item theSize;
    Item head; ///< the index of the first free stack element or NilItem
    /// Page number storage. Stack elements are linked to each other, forming
    /// an array-based linked list.
    Ipc::Mem::FlexibleArray<Item> theItems;
    // No more data members should follow! See Ipc::Mem::FlexibleArray<> for details.
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_STACK_H

