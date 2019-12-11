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
#include "MasterXaction.h" /* XXX: for Stopwatch */

template <class Member>
static inline void
ReportOneRusageChange(std::ostream &os, struct rusage &from, struct rusage &to, const Member member, const char *label)
{
    if (from.*member != to.*member)
        os << Debug::Extra << label << ':' << ' ' << (to.*member - from.*member);
}

static void
ReportRusageChange(std::ostream &os, struct rusage &from, struct rusage &to)
{
    ReportOneRusageChange(os, from, to, &rusage::ru_maxrss, "maximum-resident-set-size");
    ReportOneRusageChange(os, from, to, &rusage::ru_minflt, "soft-page-faults");
    ReportOneRusageChange(os, from, to, &rusage::ru_majflt, "hard-page-faults");
    ReportOneRusageChange(os, from, to, &rusage::ru_nswap, "swaps");
    ReportOneRusageChange(os, from, to, &rusage::ru_inblock, "block-input-operations");
    ReportOneRusageChange(os, from, to, &rusage::ru_oublock, "block-output-operations");
    ReportOneRusageChange(os, from, to, &rusage::ru_nsignals, "signals-received");
    ReportOneRusageChange(os, from, to, &rusage::ru_nvcsw, "voluntary-context-switches");
    ReportOneRusageChange(os, from, to, &rusage::ru_nivcsw, "involuntary-context-switches");
}

namespace Ipc
{
namespace Mem
{

/// helper class to report suspiciously long "optimistic search" loops
class LoopTimer
{
public:
    LoopTimer(const char *operation, const PageStack &stack);

    void noteStart() { getRusage(usageAtStart); iterations = 0; stopwatch.resume(); }
    void noteFinish(const bool result) { checkpoint(result, stopwatch.pause()); }
    void noteIteration() { ++iterations; }

private:
    // minimum duration we should report next (may increase to reduce noise)
    std::chrono::nanoseconds reportableDuration = std::chrono::nanoseconds(10000);
    // minimum duration we should report always (fixed)
    const std::chrono::seconds hugeDuration = std::chrono::seconds(1);

    void checkpoint(const bool result, const Stopwatch::Clock::duration duration);
    void getRusage(struct rusage &rusage) const;

    Stopwatch stopwatch;
    struct rusage usageAtStart; ///< resource usage at noteStart() time
    uint64_t iterations = 0;

    const PageStack &stack_; ///< the stack which loops we are measuring
    const char * const operation_ = nullptr; ///< stack's method being measured
};

} // namespace Mem
} // namespace Ipc

/* Ipc::Mem::LoopTimer */

Ipc::Mem::LoopTimer::LoopTimer(const char *operation, const PageStack &stack):
    stack_(stack),
    operation_(operation)
{
}

void
Ipc::Mem::LoopTimer::getRusage(struct rusage &usage) const
{
    // XXX: Merge with squid_getrusage() as squid_fast_getrusage() or RUsage::?
    const auto ok = getrusage(RUSAGE_THREAD, &usage) == 0;
    assert(ok); // XXX
}

void
Ipc::Mem::LoopTimer::checkpoint(const bool result, const Stopwatch::Clock::duration duration)
{
    if (duration >= reportableDuration) {
        reportableDuration *= 2;
        if (reportableDuration > hugeDuration)
            reportableDuration = hugeDuration;

        if (Debug::Enabled(54, Important(62))) {
            struct rusage rusageAtEnd;
            getRusage(rusageAtEnd);
            auto &os = Debug::Start(54, DBG_IMPORTANT);

            os << "WARNING: shm page search took too long:" <<
                Debug::Extra << "duration: " << std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count() << "ns" <<
                Debug::Extra << "iterations: " << iterations <<
                Debug::Extra << "result: " << (result ? "success" : "failure") <<
                Debug::Extra << "free pages: " << stack_.theSize <<
                Debug::Extra << "total pages: " << stack_.theCapacity <<
                Debug::Extra << "searches seen: " << stopwatch.busyPeriodCount() <<
                Debug::Extra << "mean duration: " << std::chrono::nanoseconds(stopwatch.busyPeriodMean()).count() << "ns" <<
                Debug::Extra << "shm page stack operation: " << operation_ <<
                Debug::Extra << "shm page stack ID: " << stack_.thePoolId <<
                Debug::Extra << "next report threshold: " << std::chrono::duration_cast<std::chrono::nanoseconds>(reportableDuration).count() << "ns";

            ReportRusageChange(os, usageAtStart, rusageAtEnd);
            Debug::Finish();
        }
    }
}

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

    static LoopTimer loopTimer("pop", *this);
    loopTimer.noteStart();

    Slot::Pointer current = head_.load();

    auto nextFree = Slot::NilPtr;
    do {
        if (current == Slot::NilPtr) {
            loopTimer.noteFinish(false);
            return false;
        }
        loopTimer.noteIteration();
        nextFree = slots_[current].next();
    } while (!head_.compare_exchange_weak(current, nextFree));

    // must decrement after removing the page to avoid underflow
    const auto newSize = --theSize;
    assert(newSize < theCapacity);

    slots_[current].take();
    page.number = current + 1;
    page.pool = thePoolId;
    debugs(54, 8, page << " size: " << newSize);
    loopTimer.noteFinish(true);
    return true;
}

void
Ipc::Mem::PageStack::push(PageId &page)
{
    debugs(54, 8, page);
    assert(page);
    assert(pageIdIsValid(page));

    static LoopTimer loopTimer("push", *this);
    loopTimer.noteStart();

    const auto pageIndex = page.number - 1;
    auto &slot = slots_[pageIndex];

    // must increment before inserting the page to avoid underflow in pop()
    const auto newSize = ++theSize;
    assert(newSize <= theCapacity);

    auto current = head_.load();
    auto expected = Slot::TakenPage;
    do {
        loopTimer.noteIteration();

        slot.put(expected, current);
        expected = current;
    } while (!head_.compare_exchange_weak(current, pageIndex));

    debugs(54, 8, page << " size: " << newSize);
    page = PageId();
    loopTimer.noteFinish(true);
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

