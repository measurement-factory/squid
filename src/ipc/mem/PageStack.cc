/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"

#include "base/TextException.h"
#include "Debug.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"

/// used to mark a stack slot available for storing free page offsets
const Ipc::Mem::PageStack::Value Writable = 0;

Ipc::Mem::PageStack::PageStack(const uint32_t aPoolId, const unsigned int aCapacity, const size_t aPageSize):
    thePoolId(aPoolId), theCapacity(aCapacity), thePageSize(aPageSize),
    theSize(theCapacity),
    head(theCapacity - 1),
    theItems(aCapacity)
{
    assert(theCapacity < NoItem);
    // initially, all pages are free
    theItems[0] = NilItem;
    for (Value i = 1; i < theSize; ++i)
        theItems[i].store(i - 1);
}

/*
 * TODO: We currently rely on the theLastReadable hint during each
 * loop iteration. We could also use hint just for the start position:
 * (const Offset start = theLastReadable) and then scan the stack
 * sequentially regardless of theLastReadable changes by others. Which
 * approach is better? Same for push().
 */
bool
Ipc::Mem::PageStack::pop(PageId &page)
{
    Must(!page);

    // we may fail to dequeue, but be conservative to prevent long searches
    --theSize;
    Value prev = 0;
    Value current = head.load();

    do {
        if (current == NilItem) {
            ++theSize;
            return false;
        }
        prev = theItems[current].load();
        // TODO: report suspiciously long loops
    } while (!head.compare_exchange_weak(current, prev));

    const auto poppedPrev = theItems[current].exchange(NoItem);
    assert(poppedPrev != NoItem);
    page.number = current + 1;
    page.pool = thePoolId;
    debugs(54, 9, page << " at " << current << " size: " << theSize);
    return true;
}

void
Ipc::Mem::PageStack::push(PageId &page)
{
    debugs(54, 9, page);

    if (!page)
        return;

    Must(pageIdIsValid(page));

    const auto pageIndex = page.number - 1;
    Value current = head.load();
    unsigned int tries = 0;

    do {
        const auto prev = theItems[pageIndex].exchange(current);
        assert((!tries && prev == NoItem) || (tries && prev != NoItem));
        ++tries;
        // TODO: report suspiciously long loops
    } while (!head.compare_exchange_weak(current, pageIndex));

    theSize++;
    debugs(54, 9, page << " at " << current << " size: " << theSize);
    page = PageId();
}

bool
Ipc::Mem::PageStack::pageIdIsValid(const PageId &page) const
{
    return page.pool == thePoolId && page.number != 0 &&
           page.number <= capacity();
}

size_t
Ipc::Mem::PageStack::sharedMemorySize() const
{
    return SharedMemorySize(thePoolId, theCapacity, thePageSize);
}

size_t
Ipc::Mem::PageStack::SharedMemorySize(const uint32_t, const unsigned int capacity, const size_t pageSize)
{
    const size_t levelsSize = PageId::maxPurpose * sizeof(std::atomic<Ipc::Mem::PageStack::Value>);
    const size_t pagesDataSize = capacity * pageSize;
    return StackSize(capacity) + LevelsPaddingSize(capacity) + levelsSize + pagesDataSize;
}

size_t
Ipc::Mem::PageStack::StackSize(const unsigned int capacity)
{
    return sizeof(PageStack) + capacity * sizeof(Item);
}

size_t
Ipc::Mem::PageStack::stackSize() const
{
    return StackSize(theCapacity);
}

size_t
Ipc::Mem::PageStack::LevelsPaddingSize(const unsigned int capacity)
{
    const auto displacement = StackSize(capacity) % alignof(Levels_t);
    return displacement ? alignof(Levels_t) - displacement : 0;
}

