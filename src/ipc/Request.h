/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_REQUEST_H
#define SQUID_IPC_REQUEST_H

#include "base/RefCount.h"
#include "base/TypeTraits.h"
#include "ipc/forward.h"
#include "ipc/QuestionerId.h"

namespace Ipc
{

/// IPC request
class Request: public RefCountable, public Interface
{
public:
    typedef RefCount<Request> Pointer;

public:
    Request(const int aRequestorId, const unsigned int aRequestId, const bool initQuid):
        requestorId(aRequestorId), requestId(aRequestId), qid(initQuid) {}

    virtual void pack(TypedMsgHdr& msg) const = 0; ///< prepare for sendmsg()
    virtual Pointer clone() const = 0; ///< returns a copy of this

public:
    int requestorId; ///< kidId of the requestor; used for response destination
    unsigned int requestId; ///< unique for sender; matches request w/ response
    QuestionerId qid; ///< an identifier of the kid process initiated this IPC question
};

} // namespace Ipc

#endif /* SQUID_IPC_REQUEST_H */

