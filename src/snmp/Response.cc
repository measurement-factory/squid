/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/Messages.h"
#include "ipc/Request.h"
#include "ipc/TypedMsgHdr.h"
#include "snmp/Request.h"
#include "snmp/Response.h"

std::ostream& Snmp::operator << (std::ostream& os, const Response& response)
{
    os << "{requestId: " << response.requestId << " qid: " << response.qid << '}';
    return os;
}

Snmp::Response::Response(const Request &request):
    Ipc::Response(request.requestId, request.qid), pdu()
{
}

Snmp::Response::Response(const Ipc::TypedMsgHdr& msg):
    Ipc::Response(0)
{
    msg.checkType(Ipc::mtSnmpResponse);
    msg.getPod(requestId);
    qid.unpack(msg);
    pdu.unpack(msg);
}

void
Snmp::Response::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtSnmpResponse);
    msg.putPod(requestId);
    qid.pack(msg);
    pdu.pack(msg);
}

Ipc::Response::Pointer
Snmp::Response::clone() const
{
    return new Response(*this);
}

