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
#include "base/TypeTraits.h"
#include "ipc/forward.h"
#include "ipc/QuestionerId.h"

namespace Ipc
{

/// A response to Ipc::Request.
class Response: public RefCountable, public Interface
{
public:
    typedef RefCount<Response> Pointer;

public:
    virtual void pack(TypedMsgHdr& msg) const = 0; ///< prepare for sendmsg()
    virtual Pointer clone() const = 0; ///< returns a copy of this

public:
    unsigned int requestId; ///< ID of request we are responding to
    QuestionerId qid; ///< an identifier of the kid process initiated this IPC question

protected:
    /// sender's constructor
    Response(const unsigned int aRequestId, const Ipc::QuestionerId aQid):
        requestId(aRequestId),
        qid(aQid)
    {
    }

    /// recipient's constructor
    Response(): requestId(0) {} // TODO: Use "= default"
};

} // namespace Ipc

#endif /* SQUID_IPC_RESPONSE_H */

