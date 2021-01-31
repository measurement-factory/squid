/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionCreator.h"
#include "mgr/ActionProfile.h"
#include "mgr/Request.h"
#include "mgr/Response.h"

Mgr::Response::Response(const Ipc::Request::Pointer &request, const Action::Pointer &anAction):
    Ipc::Response(request->requestId, request->qid), action(anAction)
{
    Must(action->name()); // the action must be named
}

Mgr::Response::Response(const Request &request):
    Ipc::Response(request.requestId, request.qid)
{
}

Mgr::Response::Response(const Ipc::TypedMsgHdr& msg):
    Ipc::Response(0)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(requestId);
    Must(requestId != 0);
    qid.unpack(msg);

    if (msg.hasMoreData()) {
        String actionName;
        msg.getString(actionName);
        action = CacheManager::GetInstance()->createNamedAction(actionName.termedBuf());
        Must(hasAction());
        action->unpack(msg);
    }
}

void
Mgr::Response::pack(Ipc::TypedMsgHdr& msg) const
{
    Must(requestId != 0);
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(requestId);
    qid.pack(msg);
    if (hasAction()) {
        msg.putString(action->name());
        action->pack(msg);
    }
}

Ipc::Response::Pointer
Mgr::Response::clone() const
{
    return new Response(*this);
}

bool
Mgr::Response::hasAction() const
{
    return action != NULL;
}

const Mgr::Action&
Mgr::Response::getAction() const
{
    Must(hasAction());
    return *action;
}

