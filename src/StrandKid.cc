/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CbcPointer.h"
#include "ip/Address.h"
#include "ipc/Messages.h"
#include "ipc/SharedListen.h"
#include "ipc/Strand.h"
#include "ipc/StrandCoord.h"
#include "sbuf/SBuf.h"
#include "StrandKid.h"
#include "tools.h"

// XXX: Merge with ipc/Strand.cc Strand_ instead of having two disjoint states!
// TODO: Rename to Strand after completing StrandJob TODO in Strand.h.
/// A singleton for managing Strand artifacts that may outlive Strand job.
/// Accessible via TheStrand().
class Strand_
{
public:
    /// allows mtFindStrand queries to find this strand
    /// \sa Strand::InitTagged()
    std::optional<SBuf> tag;

    /// a task waiting for other kids to reach the same synchronization point
    AsyncCallPointer synchronizationCallback;

    /// tracks Ipc::Strand::BarrierWait() synchronization activity
    Instance::OptionalStartupActivityTracker synchronizationTracker;
};

/// the only Strand_ object in existence
static auto &
TheStrand()
{
    static const auto strand = new Strand_();
    return *strand;
}

void
StrandBarrierWait(const AsyncCallPointer &cb)
{
    Assure(cb);
    Assure(!TheStrand().synchronizationCallback);
    TheStrand().synchronizationCallback = cb;

    // we could simply use cb->detach(), but call name is usually more useful
    // for "current startup activities" triage dumps
    const auto trackerId = ScopedId(cb->name, cb->id.value);
    TheStrand().synchronizationTracker.start(trackerId);

    Ipc::StrandMessage::NotifyCoordinator(Ipc::mtSynchronizationRequest, nullptr);
}

/// handles Coordinator response to our StrandBarrierWait() request
static void
HandleSynchronizationResponse(const Ipc::TypedMsgHdr &rawMessage)
{
    (void)Ipc::Mine(Ipc::SynchronizationResponse(rawMessage));

    auto &synchronizationCallback = TheStrand().synchronizationCallback;
    debugs(54, 2, " has " << synchronizationCallback);
    Assure(synchronizationCallback);
    ScheduleCallHere(synchronizationCallback);
    synchronizationCallback = nullptr;

    TheStrand().synchronizationTracker.finish();
}

void
InitStrand()
{
    Assure(UsingSmp());
    Assure(!IamCoordinatorProcess());

    static auto initializationTag = TheStrand().tag;
    Assure(initializationTag == TheStrand().tag); // bans { InitStrand(), TagStrand() } sequence

    static auto started = false;
    if (!started) {
        started = true;
        // TODO: Consider adding CbcPointer::Make(), similar to RefCount::Make().
        const auto strand = CbcPointer<Ipc::Strand>(new Ipc::Strand(initializationTag));
        strand->configureMessageHandler(Ipc::mtSynchronizationResponse, HandleSynchronizationResponse);
        AsyncJob::Start(strand);
    }
}

void
TagStrand(const SBuf &aTag)
{
    Assure(aTag.length());

    auto &tag = TheStrand().tag;

    if (tag) {
        Assure(tag == aTag);
        return; // already initialized
    }

    tag = aTag;
    InitStrand(); // XXX
}

