/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 17    Request Forwarding */

#include "squid.h"
#include "base/AsyncFunCalls.h"
#include "base/IoManip.h"
#include "CollapsedForwarding.h"
#include "globals.h"
#include "ipc/mem/Segment.h"
#include "ipc/Messages.h"
#include "ipc/Port.h"
#include "ipc/TypedMsgHdr.h"
#include "MemObject.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store_key_md5.h"
#include "tools.h"

/// shared memory segment path to use for CollapsedForwarding queue
static const char *const ShmLabel = "cf";
/// a single worker-to-worker queue capacity
// TODO: make configurable or compute from squid.conf settings if possible
static const int QueueCapacity = 1024;

std::unique_ptr<CollapsedForwarding::Queue> CollapsedForwarding::queue;

/// IPC queue message
class CollapsedForwardingMsg
{
public:
    CollapsedForwardingMsg(): sender(-1), xitIndex(-1) {}

    /// prints message parameters; suitable for cache manager reports
    void stat(std::ostream &);

public:
    int sender; ///< kid ID of sending process

    /// transients index, so that workers can find [private] entries to sync
    sfileno xitIndex;
};

void
CollapsedForwardingMsg::stat(std::ostream &os)
{
    os << "sender: " << sender << ", xitIndex: " << xitIndex;
}

// CollapsedForwarding

void
CollapsedForwarding::Init()
{
    Must(!queue.get());
    if (UsingSmp() && IamWorkerProcess()) {
        queue.reset(new Queue(ShmLabel, KidIdentifier));
        AsyncCall::Pointer callback = asyncCall(17, 4, "CollapsedForwarding::HandleNewDataAtStart",
                                                NullaryFunDialer(&CollapsedForwarding::HandleNewDataAtStart));
        ScheduleCallHere(callback);
    }
}

/// implements the guts of two public Broadcast() functions
template <typename CallerContextReporter>
void
CollapsedForwarding::Broadcast_(const sfileno index, const bool includingThisWorker, const CallerContextReporter &callerContextReporter)
{
    if (!queue.get())
        return;

    CollapsedForwardingMsg msg;
    msg.sender = KidIdentifier;
    msg.xitIndex = index;

    // TODO: send only to workers who are waiting for data
    for (int workerId = 1; workerId <= Config.workers; ++workerId) {
        try {
            if ((workerId != KidIdentifier || includingThisWorker) && queue->push(workerId, msg))
                Notify(workerId);
        } catch (const Queue::Full &) {
            debugs(17, DBG_IMPORTANT, "ERROR: SMP Store synchronization queue overflow for kid" << workerId <<
                   " at " << queue->outSize(workerId) << " items" << CallToPrint(callerContextReporter));
            // TODO: grow queue size
        }
    }
}

void
CollapsedForwarding::Broadcast(const StoreEntry &e, const SourceLocation &caller, const bool includingThisWorker)
{
    if (!e.hasTransients() ||
            !Store::Root().transientReaders(e)) {
        debugs(17, 7, "nobody reads " << e << "; broadcaster: " << caller);
        if (e.mem_obj)
            e.mem_obj->sawChangesToBroadcast = false; // may already be false
        return;
    }

    debugs(17, 5, e << "; broadcaster: " << caller);
    e.mem_obj->sawChangesToBroadcast = false; // may already be false
    const auto debugExtras = [&e, &caller](std::ostream &os) {
        os <<
            Debug::Extra << "broadcaster: " << caller <<
            Debug::Extra << "Store entry: " << e;
        if (e.mem_obj->request)
            os << Debug::Extra << "storing master transaction: " << e.mem_obj->request->masterXaction->id;
    };
    Broadcast_(e.mem_obj->xitTable.index, includingThisWorker, debugExtras);
}

void
CollapsedForwarding::Broadcast(const sfileno index, const SourceLocation &caller, const bool includingThisWorker)
{
    if (!queue.get())
        return;

    debugs(17, 7, "entry " << index << " to " << Config.workers << (includingThisWorker ? "" : "-1") << " workers; broadcaster: " << caller);
    const auto debugExtras = [index, &caller](std::ostream &os) {
        os <<
            Debug::Extra << "broadcaster: " << caller <<
            Debug::Extra << "transients entry ID: " << index;
    };
    Broadcast_(index, includingThisWorker, debugExtras);
}

void
CollapsedForwarding::Notify(const int workerId)
{
    // TODO: Count and report the total number of notifications, pops, pushes.
    debugs(17, 7, "to kid" << workerId);
    Ipc::TypedMsgHdr msg;
    msg.setType(Ipc::mtCollapsedForwardingNotification);
    msg.putInt(KidIdentifier);
    const String addr = Ipc::Port::MakeAddr(Ipc::strandAddrLabel, workerId);
    Ipc::SendMessage(addr, msg);
}

void
CollapsedForwarding::HandleNewData(const char *const when)
{
    debugs(17, 4, "popping all " << when);
    CollapsedForwardingMsg msg;
    int workerId;
    int poppedCount = 0;
    while (queue->pop(workerId, msg)) {
        debugs(17, 3, "message from kid" << workerId);
        if (workerId != msg.sender) {
            debugs(17, DBG_IMPORTANT, "mismatching kid IDs: " << workerId <<
                   " != " << msg.sender);
        }

        debugs(17, 7, "handling entry " << msg.xitIndex << " in transients_map");
        Store::Root().syncCollapsed(msg.xitIndex);
        debugs(17, 7, "handled entry " << msg.xitIndex << " in transients_map");

        // XXX: stop and schedule an async call to continue
        ++poppedCount;
        assert(poppedCount < SQUID_MAXFD);
    }
}

void
CollapsedForwarding::HandleNotification(const Ipc::TypedMsgHdr &msg)
{
    const int from = msg.getInt();
    debugs(17, 7, "from " << from);
    assert(queue.get());
    queue->clearReaderSignal(from);
    HandleNewData("after notification");
}

/// Handle queued IPC messages for the first time in this process lifetime, when
/// the queue may be reflecting the state of our killed predecessor.
void
CollapsedForwarding::HandleNewDataAtStart()
{
    /// \sa IpcIoFile::HandleMessagesAtStart() -- duplicates this logic
    queue->clearAllReaderSignals();
    HandleNewData("at start");
}

void
CollapsedForwarding::StatQueue(std::ostream &os)
{
    if (queue.get()) {
        os << "Transients queues:\n";
        queue->stat<CollapsedForwardingMsg>(os);
    }
}

/// initializes shared queue used by CollapsedForwarding
class CollapsedForwardingRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    CollapsedForwardingRr(): owner(nullptr) {}
    ~CollapsedForwardingRr() override;

protected:
    void create() override;
    void open() override;

private:
    Ipc::MultiQueue::Owner *owner;
};

DefineRunnerRegistrator(CollapsedForwardingRr);

void CollapsedForwardingRr::create()
{
    Must(!owner);
    owner = Ipc::MultiQueue::Init(ShmLabel, Config.workers, 1,
                                  sizeof(CollapsedForwardingMsg),
                                  QueueCapacity);
}

void CollapsedForwardingRr::open()
{
    CollapsedForwarding::Init();
}

CollapsedForwardingRr::~CollapsedForwardingRr()
{
    delete owner;
}

/* Store::BroadcastMonitor */

Store::BroadcastMonitor::BroadcastMonitor(StoreEntry &e): entry(e)
{
    // A delayed CollapsedForwarding::Broadcast() call requires access to
    // mem_obj. We never call destroyMemoryObject() for locked entries.
    entry.lock("Store::BroadcastMonitor");

    auto &mem = entry.mem();
    // TODO: Consider converting monitoringChangesToBroadcast to boolean and
    // remembering that we were not the first to set it instead.
    ++mem.monitoringChangesToBroadcast;
    Assure(mem.monitoringChangesToBroadcast); // no overflows
}

Store::BroadcastMonitor::~BroadcastMonitor()
{
    // TODO: noexcept for CollapsedForwarding::Broadcast(), StoreEntry::unlock()
    SWALLOW_EXCEPTIONS({
        auto &mem = entry.mem();
        Assure(mem.monitoringChangesToBroadcast); // no underflows
        --mem.monitoringChangesToBroadcast;
        if (!mem.monitoringChangesToBroadcast && mem.sawChangesToBroadcast)
            CollapsedForwarding::Broadcast(entry, Here());

        entry.unlock("Store::BroadcastMonitor");
    });
}

