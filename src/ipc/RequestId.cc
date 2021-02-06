/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/QuestionerId.h"
#include "ipc/RequestId.h"

#include <iostream>

Ipc::RequestId::RequestId(const Index anIndex):
    qid_(MyQuestionerId()),
    index_(anIndex)
{
}

void Ipc::RequestId::reset(const Index anIndex)
{
    qid_ = MyQuestionerId();
    index_ = anIndex;
}

std::ostream &
Ipc::operator <<(std::ostream &os, const RequestId &requestId)
{
    os << requestId.index() << '@' << requestId.questioner();
    return os;
}

