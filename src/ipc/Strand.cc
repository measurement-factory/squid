/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "CollapsedForwarding.h"
#include "comm/Connection.h"
#include "fatal.h"
#include "globals.h"
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
#include "StrandKid.h"

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Strand);

Ipc::Strand::Strand(const std::optional<SBuf> &aTag):
    Port(MakeAddr(strandAddrLabel, KidIdentifier)),
    tag(aTag)
{
}

void
Ipc::Strand::configureMessageHandler(const MessageType mt, const MessageHandler handler)
{
    Assure(handler);
    const auto inserted = messageHandlers.emplace(mt, handler).second;
    Assure(inserted); // at most one handler is supported for each message type
}

void Ipc::Strand::start()
{
    Port::start();
    registerSelf();
}

/// whether Coordinator ACKed registration
bool
Ipc::Strand::registered() const
{
    return selfRegistrationTracker.startedAndFinished();
}

void Ipc::Strand::registerSelf()
{
    debugs(54, 6, MYNAME);
    Must(!registered());

    selfRegistrationTracker.start(ScopedId("Ipc::Strand self-registration"));
    NotifyCoordinator(mtRegisterStrand, tag);
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

    default:
        // TODO: Remove hard-coded links to other modules by migrating the above
        // hard-coded cases (except mtStrandRegistered) to use messageHandlers.

        // TODO: Consider using an AsyncCallback Subscription; requires copying
        // `message` (currently around 4KB in size) for asynchronous delivery.
        const auto handler = messageHandlers.find(message.rawType());
        if (handler != messageHandlers.end())
            return handler->second(message);

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
        Assure(!registered());
        selfRegistrationTracker.finish();
        Assure(registered());
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

void Ipc::Strand::timedout()
{
    debugs(54, 6, registered());
    // TODO: Replace this guard with Assure() when clearTimeout() reliably cancels callbacks.
    if (!registered())
        fatalf("kid%d registration timed out", KidIdentifier);
}

