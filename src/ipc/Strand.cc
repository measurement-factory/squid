/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/CbcPointer.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "CollapsedForwarding.h"
#include "comm/Connection.h"
#include "fatal.h"
#include "globals.h"
#include "Instance.h"
#include "ipc/Kids.h"
#include "ipc/Messages.h"
#include "ipc/QuestionerId.h"
#include "ipc/SharedListen.h"
#include "ipc/Strand.h"
#include "ipc/StrandCoord.h"
#include "ipc/StrandSearch.h"
#include "mgr/Forwarder.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#if HAVE_DISKIO_MODULE_IPCIO
#include "DiskIO/IpcIo/IpcIoFile.h" /* XXX: scope boundary violation */
#endif
#if SQUID_SNMP
#include "snmp/Forwarder.h"
#include "snmp/Request.h"
#include "snmp/Response.h"
#endif

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Strand);

// XXX: This method should not exist because one should not synchronously
// communicate with a started job -- the job object may disappear even if its
// doneAll() method never returns true. Thus, externally accessible services
// like barrierWait() must be implemented outside of Strand's job class, with
// Strand job accessing them (e.g., to call synchronizationCallback) instead of
// the other way around. TODO: Until we need support for multiple barriers, call
// a hard-coded handler (e.g., ListeningManager::NoteAllAreReadyToListen()).
//
// There is an equivalent XXX in easier-to-refactor Coordinator::Instance().
Ipc::Strand &
Ipc::Strand::Instance()
{
    static const auto instance = new Strand();

    static auto started = false;
    if (!started) {
        started = true;
        AsyncJob::Start(instance);
    }

    return *instance;
}

void
Ipc::Strand::Init()
{
    Assure(UsingSmp());
    Assure(!IamCoordinatorProcess());
    (void)Instance(); // used for its AsyncJob::Start() side effect
}

Ipc::Strand::Strand():
    Port(MakeAddr(strandAddrLabel, KidIdentifier)),
    isRegistered(false)
{
}

void Ipc::Strand::start()
{
    Port::start();
    registerSelf();
}

void Ipc::Strand::barrierWait(const AsyncCallPointer &cb)
{
    Assure(cb);
    Assure(!synchronizationCallback);
    synchronizationCallback = cb;
    debugs(2,2, getpid() << ' ' << this << " set " << synchronizationCallback->id);

    Instance::StartupActivityStarted(synchronizationCallback->id.detach());
    StrandMessage::NotifyCoordinator(mtSynchronizationRequest, nullptr);

    debugs(2,2, getpid() << ' ' << this << " has " << synchronizationCallback->id);
}

void Ipc::Strand::registerSelf()
{
    debugs(54, 6, MYNAME);
    Must(!isRegistered);

    StrandMessage::NotifyCoordinator(mtRegisterStrand, nullptr);
    setTimeout(6, "Ipc::Strand::timeoutHandler"); // TODO: make 6 configurable?
}

void Ipc::Strand::receive(const TypedMsgHdr &message)
{
    switch (message.rawType()) {

    case mtStrandRegistered:
        handleRegistrationResponse(Mine(StrandMessage(message)));
        break;

    case mtSharedListenResponse:
        SharedListenJoined(Mine(SharedListenResponse(message)));
        break;

#if HAVE_DISKIO_MODULE_IPCIO
    case mtStrandReady:
        IpcIoFile::HandleOpenResponse(Mine(StrandMessage(message)));
        break;

    case mtIpcIoNotification:
        IpcIoFile::HandleNotification(message);
        break;
#endif /* HAVE_DISKIO_MODULE_IPCIO */

    case mtCacheMgrRequest: {
        const Mgr::Request req(message);
        handleCacheMgrRequest(req);
    }
    break;

    case mtCacheMgrResponse: {
        const Mgr::Response resp(message);
        handleCacheMgrResponse(Mine(resp));
    }
    break;

    case mtCollapsedForwardingNotification:
        CollapsedForwarding::HandleNotification(message);
        break;

#if SQUID_SNMP
    case mtSnmpRequest: {
        const Snmp::Request req(message);
        handleSnmpRequest(req);
    }
    break;

    case mtSnmpResponse: {
        const Snmp::Response resp(message);
        handleSnmpResponse(Mine(resp));
    }
    break;
#endif

    case mtSynchronizationResponse: {
        debugs(54, 6, "Synchronization response");
        handleSynchronizationResponse(Mine(SynchronizationResponse(message)));
    }
    break;

    default:
        Port::receive(message);
        break;
    }
}

void
Ipc::Strand::handleRegistrationResponse(const StrandMessage &msg)
{
    // handle registration response from the coordinator; it could be stale
    if (msg.strand.kidId == KidIdentifier && msg.strand.pid == getpid()) {
        debugs(54, 6, "kid" << KidIdentifier << " registered");
        clearTimeout(); // we are done
    } else {
        // could be an ACK to the registration message of our dead predecessor
        debugs(54, 6, "kid" << KidIdentifier << " is not yet registered");
        // keep listening, with a timeout
    }
}

void Ipc::Strand::handleCacheMgrRequest(const Mgr::Request& request)
{
    Mgr::Action::Pointer action =
        CacheManager::GetInstance()->createRequestedAction(request.params);
    action->respond(request);
}

void Ipc::Strand::handleCacheMgrResponse(const Mgr::Response& response)
{
    Mgr::Forwarder::HandleRemoteAck(response.requestId);
}

#if SQUID_SNMP
void Ipc::Strand::handleSnmpRequest(const Snmp::Request& request)
{
    debugs(54, 6, MYNAME);
    Snmp::SendResponse(request.requestId, request.pdu);
}

void Ipc::Strand::handleSnmpResponse(const Snmp::Response& response)
{
    debugs(54, 6, MYNAME);
    Snmp::Forwarder::HandleRemoteAck(response.requestId);
}
#endif

void
Ipc::Strand::handleSynchronizationResponse(const SynchronizationResponse &)
{
    debugs(2,2, getpid() << ' ' << this << " has " << synchronizationCallback);
    Assure(synchronizationCallback);
    ScheduleCallHere(synchronizationCallback);
    Instance::StartupActivityFinished(synchronizationCallback->id.detach());
    synchronizationCallback = nullptr;
}

void Ipc::Strand::timedout()
{
    debugs(54, 6, isRegistered);
    if (!isRegistered)
        fatalf("kid%d registration timed out", KidIdentifier);
}

