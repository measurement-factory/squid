/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_RESPONSE_H
#define SQUID_IPC_RESPONSE_H

#include "base/RefCount.h"
#include "ipc/forward.h"
#include "ipc/QuestionId.h"

namespace Ipc
{

/// A response to Ipc::Request.
class Response: public RefCountable
{
public:
    typedef RefCount<Response> Pointer;

public:
    explicit Response(unsigned int aRequestId):
        requestId(aRequestId), qid(false) {}

    Response(unsigned int aRequestId, const Ipc::QuestionerId &aQid):
        requestId(aRequestId), qid(aQid) {}

    virtual void pack(TypedMsgHdr& msg) const = 0; ///< prepare for sendmsg()
    virtual Pointer clone() const = 0; ///< returns a copy of this

public:
    unsigned int requestId; ///< ID of request we are responding to
    const QuestionerId qid;
};

inline
std::ostream& operator << (std::ostream &os, const Response& response)
{
    os << "[response.requestId %u]" << response.requestId << " qid: " << response.qid << '}';
    return os;
}

} // namespace Ipc

#endif /* SQUID_IPC_RESPONSE_H */

