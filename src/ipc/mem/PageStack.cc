/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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

/* Ipc::Mem::PageStackStorageSlot */

// We are using uint32_t for Pointer because PageId::number is uint32_t.
// PageId::number should probably be uint64_t to accommodate larger caches.
static_assert(sizeof(Ipc::Mem::PageStackStorageSlot::Pointer) ==
    sizeof(decltype(Ipc::Mem::PageId::number)));

void
Ipc::Mem::PageStackStorageSlot::take()
{
    const auto next = nextOrMarker.exchange(TakenPage);
    assert(next != TakenPage);
}

void
Ipc::Mem::PageStackStorageSlot::put(const PointerOrMarker expected, const Pointer next)
{
    assert(next != TakenPage);
    const auto old = nextOrMarker.exchange(next);
    assert(old == expected);
}

/* Ipc::Mem::PageStack */

Ipc::Mem::PageStack::PageStack(const uint32_t aPoolId, const unsigned int aCapacity, const size_t aPageSize):
    thePoolId(aPoolId), theCapacity(aCapacity), thePageSize(aPageSize),
    theSize(0),
    head_(Slot::NilPtr),
    slots_(aCapacity)
{
    assert(theCapacity < Slot::TakenPage);
    assert(theCapacity < Slot::NilPtr);

    // initially, all pages are free
    if (theCapacity) {
        const auto lastIndex = theCapacity-1;
        // FlexibleArray cannot construct its phantom elements so, technically,
        // all slots (except the very first one) are uninitialized until now.
        for (Slot::Pointer i = 0; i < lastIndex; ++i)
            (void)new(&slots_[i])Slot(i+1);
        (void)new(&slots_[lastIndex])Slot(Slot::NilPtr);
        theSize = theCapacity;
        head_ = 0;
    }
}

bool
Ipc::Mem::PageStack::pop(PageId &page)
{
    assert(!page);

    Slot::Pointer current = head_.load();

    auto nextFree = Slot::NilPtr;
    do {
        if (current == Slot::NilPtr)
            return false;
        nextFree = slots_[current].next();
        // TODO: report suspiciously long loops
    } while (!head_.compare_exchange_weak(current, nextFree));

    // must decrement after removing the page to avoid underflow
    const auto newSize = --theSize;
    assert(newSize < theCapacity);

    slots_[current].take();
    page.number = current + 1;
    page.pool = thePoolId;
    debugs(54, 8, page << " size: " << newSize);
    return true;
}

void
Ipc::Mem::PageStack::push(PageId &page)
{
    debugs(54, 8, page);
    assert(page);
    assert(pageIdIsValid(page));

    const auto pageIndex = page.number - 1;
    auto &slot = slots_[pageIndex];

    // must increment before inserting the page to avoid underflow in pop()
    const auto newSize = ++theSize;
    assert(newSize <= theCapacity);

    auto current = head_.load();
    auto expected = Slot::TakenPage;
    do {
        slot.put(expected, current);
        expected = current;
        // TODO: report suspiciously long loops
    } while (!head_.compare_exchange_weak(current, pageIndex));

    debugs(54, 8, page << " size: " << newSize);
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
    const size_t levelsSize = PageId::maxPurpose * sizeof(std::atomic<size_t>);
    const size_t pagesDataSize = capacity * pageSize;
    return StackSize(capacity) + pagesDataSize + levelsSize;
}

size_t
Ipc::Mem::PageStack::StackSize(const unsigned int capacity)
{
    return sizeof(PageStack) + capacity * sizeof(Slot);
}

size_t
Ipc::Mem::PageStack::stackSize() const
{
    return StackSize(theCapacity);
}

