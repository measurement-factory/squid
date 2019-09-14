/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "AccessLogEntry.h"
#include "base/AsyncCall.h"
#include "base/AsyncJob.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "cbdata.h"
#include "MemBuf.h"

#include <ostream>

static void PushCallContext(const AccessLogEntryPointer &);
static void PopCallContext();
/// XXX: Move to header
extern std::ostream &CurrentAsyncContext(std::ostream &);

InstanceIdDefinitions(AsyncJob, "job");

AsyncJob::Pointer AsyncJob::Start(AsyncJob *j)
{
    AsyncJob::Pointer job(j);
    CallJobHere(93, 5, job, AsyncJob, start);
    return job;
}

AsyncJob::AsyncJob(const char *aTypeName) :
    stopReason(NULL), typeName(aTypeName), inCall(NULL)
{
    debugs(93,5, "AsyncJob constructed, this=" << this <<
           " type=" << typeName << " [" << id << ']');
}

AsyncJob::~AsyncJob()
{
    debugs(93,5, "AsyncJob destructed, this=" << this <<
           " type=" << typeName << " [" << id << ']');
}

AccessLogEntryPointer
AsyncJob::accessLogEntry() const
{
    return nullptr; // XXX: should return global ptr set by loopers
}

void AsyncJob::start()
{
}

// XXX: temporary code to replace calls to "delete this" in jobs-in-transition.
// Will be replaced with calls to mustStop() when transition is complete.
void AsyncJob::deleteThis(const char *aReason)
{
    Must(aReason);
    stopReason = aReason;
    if (inCall != NULL) {
        // if we are in-call, then the call wrapper will delete us
        debugs(93, 4, typeName << " will NOT delete in-call job, reason: " << stopReason);
        return;
    }

    // there is no call wrapper waiting for our return, so we fake it
    debugs(93, 5, typeName << " will delete this, reason: " << stopReason);
    CbcPointer<AsyncJob> self(this);
    AsyncCall::Pointer fakeCall = asyncCall(93,4, "FAKE-deleteThis",
                                            JobMemFun(self, &AsyncJob::deleteThis, aReason));
    inCall = fakeCall;
    callEnd();
//    delete fakeCall;
}

void AsyncJob::mustStop(const char *aReason)
{
    // XXX: temporary code to catch cases where mustStop is called outside
    // of an async call context. Will be removed when that becomes impossible.
    // Until then, this will cause memory leaks and possibly other problems.
    if (!inCall) {
        stopReason = aReason;
        debugs(93, 5, typeName << " will STALL, reason: " << stopReason);
        return;
    }

    Must(inCall != NULL); // otherwise nobody will delete us if we are done()
    Must(aReason);
    if (!stopReason) {
        stopReason = aReason;
        debugs(93, 5, typeName << " will stop, reason: " << stopReason);
    } else {
        debugs(93, 5, typeName << " will stop, another reason: " << aReason);
    }
}

bool AsyncJob::done() const
{
    // stopReason, set in mustStop(), overwrites all other conditions
    return stopReason != NULL || doneAll();
}

bool AsyncJob::doneAll() const
{
    return true; // so that it is safe for kids to use
}

bool AsyncJob::canBeCalled(AsyncCall &call) const
{
    if (inCall != NULL) {
        // This may happen when we have bugs or some module is not calling
        // us asynchronously (comm used to do that).
        debugs(93, 5, HERE << inCall << " is in progress; " <<
               call << " canot reenter the job.");
        return call.cancel("reentrant job call");
    }

    return true;
}

void AsyncJob::callStart(AsyncCall &call)
{
    // we must be called asynchronously and hence, the caller must lock us
    Must(cbdataReferenceValid(toCbdata()));

    PushCallContext(accessLogEntry());

    Must(!inCall); // see AsyncJob::canBeCalled

    inCall = &call; // XXX: ugly, but safe if callStart/callEnd,Ex are paired
    debugs(inCall->debugSection, inCall->debugLevel,
           typeName << " status in:" << status());
}

void
AsyncJob::callException(const std::exception &ex)
{
    debugs(93, 2, ex.what());
    // we must be called asynchronously and hence, the caller must lock us
    Must(cbdataReferenceValid(toCbdata()));

    mustStop("exception");
}

void AsyncJob::callEnd()
{
    if (done()) {
        debugs(93, 5, *inCall << " ends job" << status());

        AsyncCall::Pointer inCallSaved = inCall;
        void *thisSaved = this;

        swanSong();

        delete this; // this is the only place where the object is deleted

        // careful: this object does not exist any more
        debugs(93, 6, HERE << *inCallSaved << " ended " << thisSaved);
        PopCallContext(); // TODO: Add scope_guard
        return;
    }

    debugs(inCall->debugSection, inCall->debugLevel,
           typeName << " status out:" << status());
    inCall = NULL;
    PopCallContext();
}

// returns a temporary string depicting transaction status, for debugging
const char *AsyncJob::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [", 2);
    if (stopReason != NULL) {
        buf.appendf("Stopped, reason:%s", stopReason);
    }
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}


#include "HttpRequest.h"
#include "MasterXaction.h"

typedef AccessLogEntryPointer CallContext;
static CallContext CallContext_;

static void
PushCallContext(const CallContext &newCtx)
{
    if (CallContext_)
        debugs(93, DBG_IMPORTANT, "BUG: nested async call " << newCtx);
    CallContext_ = newCtx;
}

static void
PopCallContext()
{
    CallContext_ = nullptr;
}

std::ostream &
CurrentAsyncContext(std::ostream &os)
{
    if (!CallContext_)
        return os;

    const static SBuf DebugExtra("\n    ");

    const auto &ale = *CallContext_;

    if (const auto &request = ale.request) {
        if (const auto &mx = request->masterXaction)
            return os << DebugExtra << "current master transaction: " << mx->id;
    }

    // provide helpful details since we cannot identify the transaction exactly

    if (const auto &from = ale.tcpClient)
        return os << DebugExtra << "current from-client connection: " << from;
    else if (!ale.cache.caddr.isNoAddr())
        return os << DebugExtra << "current client: " << ale.cache.caddr;

    const auto optionalMethod = [&ale,&os]() {
        if (ale.hasLogMethod())
            os << ale.getLogMethod() << ' ';
        return "";
    };

    if (const auto uri = ale.effectiveVirginUrl())
        return os << DebugExtra << "current client request: " << optionalMethod() << *uri;
    else if (!ale.url.isEmpty())
        return os << DebugExtra << "current request: " << optionalMethod() << ale.url;
    else if (ale.hasLogMethod())
        return os << DebugExtra << "current request method: " << ale.getLogMethod();

    return os;
}
