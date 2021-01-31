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
#include "comm/Connection.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionParams.h"
#include "mgr/Request.h"

Mgr::Request::Request(int aRequestorId, unsigned int aRequestId, const Comm::ConnectionPointer &aConn,
                      const ActionParams &aParams):
    Ipc::Request(aRequestorId, aRequestId, true),
    conn(aConn),
    params(aParams)
{
    Must(requestorId > 0);
}

Mgr::Request::Request(const Ipc::TypedMsgHdr& msg):
    Ipc::Request(0, 0, false)
{
    msg.checkType(Ipc::mtCacheMgrRequest);
    msg.getPod(requestorId);
    msg.getPod(requestId);
    qid.unpack(msg);
    params = ActionParams(msg);

    conn = new Comm::Connection;
    conn->fd = msg.getFd();
    // For now we just have the FD.
    // Address and connectio details wil be pulled/imported by the component later
}

void
Mgr::Request::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrRequest);
    msg.putPod(requestorId);
    msg.putPod(requestId);
    qid.pack(msg);
    params.pack(msg);

    msg.putFd(conn->fd);
}

Ipc::Request::Pointer
Mgr::Request::clone() const
{
    return new Request(*this);
}

