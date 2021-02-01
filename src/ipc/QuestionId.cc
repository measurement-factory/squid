/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/QuestionId.h"
#include "ipc/TypedMsgHdr.h"
#include "sbuf/Stream.h"

Ipc::QuestionerId::QuestionerId(const bool init) :
    pid(-1)
{
    if (init)
        pid = getpid();
}

Ipc::QuestionerId::QuestionerId(const TypedMsgHdr &hdrMsg)
{
    unpack(hdrMsg);
}

void
Ipc::QuestionerId::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.putPod(pid);
}

void
Ipc::QuestionerId::unpack(const TypedMsgHdr &hdrMsg)
{
    hdrMsg.getPod(pid);
}

void
Ipc::QuestionerId::rejectAnswerIfStale() const
{
    static const auto currentPid = getpid();
    if (currentPid != pid)
        throw TextException(ToSBuf("PID mismatch: ", currentPid, "!=", pid),  Here());
}

