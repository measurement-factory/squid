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
#include "sbuf/Stream.h"
#include "tools.h"

#include <unordered_set>

/* Ipc::Mem::PageStackStorageSlot */

static_assert(sizeof(Ipc::Mem::PageStackStorageSlot::Pointer) ==
    sizeof(decltype(Ipc::Mem::PageId::number)), "page indexing types are consistent");

void
Ipc::Mem::PageStackStorageSlot::take()
{
    const auto nxt = nextOrMarker.exchange(TakenPage);
    assert(nxt != TakenPage);
}

void
Ipc::Mem::PageStackStorageSlot::put(const PointerOrMarker expected, const Pointer nxt)
{
    assert(nxt != TakenPage);
    const auto old = nextOrMarker.exchange(nxt);
    assert(old == expected);
}

/* Ipc::Mem::PageStackHeadPointer */

static_assert(sizeof(Ipc::Mem::PageStackHeadPointer) <= sizeof(uint64_t),
    "PageStackHeadPointer is likely to be lock-free on supported performance-focused platforms");

bool
Ipc::Mem::PageStackHeadPointer::operator ==(const PageStackHeadPointer &them) const
{
    return first == them.first && version == them.version;
}

/* Ipc::Mem::PageStack */

Ipc::Mem::PageStack::PageStack(const uint32_t aPoolId, const PageCount aCapacity, const size_t aPageSize):
    thePoolId(aPoolId), capacity_(aCapacity), thePageSize(aPageSize),
    size_(0),
    head_(HeadPointer({Slot::NilPtr, 0})), // XXX
    hazards_(),
    slots_(aCapacity)
{
    assert(capacity_ < Slot::TakenPage);
    assert(capacity_ < Slot::NilPtr);

    if (NumberOfKids() >= hazards_.size()) {
        throw TexcHere(ToSBuf("The total number of kid processes (", NumberOfKids(),
            ") exceeds the current internal SMP code limit (", hazards_.size()-1, ")"));
    }

    // initially, all pages are free
    if (capacity_) {
        const auto lastIndex = capacity_-1;
        // FlexibleArray cannot construct its phantom elements so, technically,
        // all slots (except the very first one) are uninitialized until now.
        for (Slot::Pointer i = 0; i < lastIndex; ++i)
            (void)new(&slots_[i])Slot(i+1);
        (void)new(&slots_[lastIndex])Slot(Slot::NilPtr);
        size_ = capacity_;
        head_.store(HeadPointer({0, 1})); // XXX
    }
}

/// initiates hazardous version maintenance
void
Ipc::Mem::PageStack::initHazardousVersion()
{
    const auto concurrencyLevel = ++hazardousVersionCount_;
    assert(concurrencyLevel > 0); // no overflows

    // if pop() finds a stale version, then this kid process was restarted, and
    // we should mimic a clearHazardousVersion() call the died kid could not run
    if (hazards_[KidIdentifier].load()) {
        assert(hazardousVersionCount_ > 1);
        --hazardousVersionCount_;
    }
}

/// forget the hazardous version recorded during the same pop() call
void
Ipc::Mem::PageStack::clearHazardousVersion()
{
    hazards_[KidIdentifier].store(0); // may already be zero or even stale
    const auto concurrencyLevel = hazardousVersionCount_--;
    assert(concurrencyLevel > 0); // no underflows
}

/// sync our hazardous version declaration and nextHead with currentHead,
/// resetting currentHead if needed to keep all three consistent
/// \retval false signals an empty stack (and the end of push)
bool
Ipc::Mem::PageStack::resetHazardousVersion(HeadPointer &currentHead, HeadPointer &nextHead)
{
    while (currentHead.first != Slot::NilPtr) {
        assert(currentHead.version);
        hazards_[KidIdentifier].store(currentHead.version);
        if (head_.load() == currentHead) {
            // success: ABA#3 has not started before/while we declared hazards

            // Another pop() may nullify A.next() without noticing our
            // currentHead.version hazard set above, but a push() will need to
            // return the head_.first value to currentHead.first after that, and
            // that is when they must notice/honor our hazard, blocking ABA#4.
            nextHead.first = slots_[currentHead.first].next(); // may be nil, taken, stale
            nextHead.version = hazardlessVersionForPop();
            return true;
        }
        // ABA#2 has happened already. Thus, it is possible that ABA#3 started
        // before we stored our hazardous version. Restart from scratch.
        currentHead = head_.load();
    }
    clearHazardousVersion();
    return false; // the stack is empty
}

/// hazardlessVersion*() helper
/// \returns the next (possibly hazardous) version
Ipc::Mem::PageStack::HeadPointer::Version
Ipc::Mem::PageStack::nextVersion() const
{
    // spread initial versions among kids to reduce collisions
    using Version = HeadPointer::Version;
    static const size_t ConcurrencyLimit = NumberOfKids() + 1;
    static Version LastVersion = KidIdentifier *
        (std::numeric_limits<Version>::max() / ConcurrencyLimit);

    static_assert(std::is_unsigned<decltype(LastVersion)>::value,
        "version iterator overflows to zero");
    const auto candidate = ++LastVersion;
    return candidate ? candidate : ++LastVersion;
}

/// \returns version that differs from any declared (at call time) hazards
/// \param lonely whether there are no other/concurrent pop() calls
/// Call via hazardlessVersionForPop() or hazardlessVersionForPush().
Ipc::Mem::PageStack::HeadPointer::Version
Ipc::Mem::PageStack::hazardlessVersion(const bool lonely) const
{
    // The ABA problem:
    // 1. an endangered pop() remembers that head is A, A.next is B and pauses
    // ... zero or more push/pop events, ending with ...
    // 2. another pop() extracts A and makes head=B
    // ... zero or more push/pop events, ending with ...
    // 3. a dangerous push() or pop() that makes head=A; A.next becomes some C
    // 4. an endangered pop() resumes and extracts A, making head=B instead of C
    //
    // Hazardous version declarations may change at any time. This method may
    // return a version that became hazardous during the search, but that is OK:
    // To prevent ABA, we only need to fail the endangered pop() in ABA#4. That
    // pop() will fail if ABA#3 sets a version different from the "hazardous"
    // version declared in ABA#1. ABA#3 starts _after_ the end of ABA#1 because
    // there is a required ABA#2 between them -- somebody needs to pop A for
    // ABA#3 to become possible. To make sure that ABA#1 ends before ABA#2 ends
    // (and, hence, before ABA#3 starts), ABA#1 must record the hazardous
    // version before that version (and A) disappear. The loop in
    // resetHazardousVersion() does that.

    // Optimization: We expect most push() and pop() calls to run solo. Without
    // other/concurrent pop() calls, there are no hazards _we_ need to avoid.
    if (lonely)
        return nextVersion();

    // to avoid an (infinitely small) probability of an infinite loop, copy all
    const auto kidCount = NumberOfKids() + 1;
    static std::unordered_set<HeadPointer::Version> versions(kidCount+1);
    versions.clear();
    for (size_t kid = 0; kid <= kidCount; ++kid) {
        if (const auto version = hazards_[kid].load())
            versions.insert(version); // may already be there
    }

    auto attemptsRemaining = versions.size() + 1;
    do {
        const auto candidate = nextVersion();
        if (versions.find(candidate) == versions.end())
            return candidate;
    } while (--attemptsRemaining);

    // Unreachable: At least one of the n+1 unique candidates must be different
    // from any of the n saved numbers.
    assert(false);
    return 0;
}

/// \returns version that differs from any declared (at call time) hazards
/// This is a hazardlessVersion() wrapper optimized for pop() context.
Ipc::Mem::PageStack::HeadPointer::Version
Ipc::Mem::PageStack::hazardlessVersionForPop() const
{
    // pop() increases hazardousVersionCount_ so level 1 means we are alone
    const auto noPops = hazardousVersionCount_ == 1;
    return hazardlessVersion(noPops);
}

/// \returns version that differs from any declared (at call time) hazards
/// This is a hazardlessVersion() wrapper optimized for push() context.
Ipc::Mem::PageStack::HeadPointer::Version
Ipc::Mem::PageStack::hazardlessVersionForPush() const
{
    // Optimization: We expect no contention in most cases.
    const auto noPops = !hazardousVersionCount_;
    return hazardlessVersion(noPops);
}

bool
Ipc::Mem::PageStack::pop(PageId &page)
{
    assert(!page);

    initHazardousVersion();
    HeadPointer current = head_.load();
    HeadPointer newHead;
    do {
        if (!resetHazardousVersion(current, newHead))
            return false; // empty stack

        // Somebody may declare our newHead.version hazardous now, but if they
        // do it for the same newHead.first pointer, then our exchange below
        // will fail (because head_ has already changed on us).

    } while (!head_.compare_exchange_weak(current, newHead));
    clearHazardousVersion();

    // must decrement after removing the page to avoid underflow
    const auto newSize = --size_;
    assert(newSize < capacity_);

    const auto pageIndex = current.first;
    slots_[pageIndex].take();
    page.number = pageIndex + 1;
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
    HeadPointer newHead{pageIndex, 0};

    // Somebody may declare our newHead.version hazardous at any time, but they
    // cannot do it for our newHead.first pointer because it is not in the stack
    // until we exchange the heads below.

    auto &slot = slots_[pageIndex];

    // must increment before inserting the page to avoid underflow in pop()
    const auto newSize = ++size_;
    assert(newSize <= capacity_);

    auto current = head_.load();
    auto expected = Slot::TakenPage;
    do {
        slot.put(expected, current.first);
        expected = current.first;
        newHead.version = hazardlessVersionForPush();
    } while (!head_.compare_exchange_weak(current, newHead));

    debugs(54, 8, page << " size: " << newSize);
    page = PageId();
}

bool
Ipc::Mem::PageStack::pageIdIsValid(const PageId &page) const
{
    return page.pool == thePoolId &&
           0 < page.number && page.number <= capacity();
}

size_t
Ipc::Mem::PageStack::sharedMemorySize() const
{
    return SharedMemorySize(thePoolId, capacity_, thePageSize);
}

size_t
Ipc::Mem::PageStack::SharedMemorySize(const uint32_t, const PageCount capacity, const size_t pageSize)
{
    const auto levelsSize = PageId::maxPurpose * sizeof(Levels_t);
    const size_t pagesDataSize = capacity * pageSize;
    return StackSize(capacity) + pagesDataSize + levelsSize;
}

size_t
Ipc::Mem::PageStack::StackSize(const PageCount capacity)
{
    return sizeof(PageStack) + capacity * sizeof(Slot);
}

size_t
Ipc::Mem::PageStack::stackSize() const
{
    return StackSize(capacity_);
}

