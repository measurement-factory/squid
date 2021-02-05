/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_REQUESTID_H
#define SQUID_IPC_REQUESTID_H

#include "ipc/forward.h"
#include "ipc/QuestionerId.h"

#include <iosfwd>

namespace Ipc
{

/// uniquely identifies an IPC request among same-type concurrent IPC requests
/// submitted by a single Squid instance
class RequestId
{
public:
    /// simple opaque ID for correlating IPC responses with pending requests
    typedef unsigned int Index;

    /// request sender's constructor
    explicit RequestId(Index);

    /// request recipient's constructor
    RequestId() = default;

    /// whether the ID is set/known
    explicit operator bool() const { return index_ != 0; }

    /// make the ID unset/unknown
    void reset() { index_ = 0; }

    /// make the ID set/known with the given index; the caller is the questioner
    void reset(Index index);

    QuestionerId questioner() const { return qid_; }
    Index index() const { return index_; }

private:
    /// who asked the question
    QuestionerId qid_;

    /// question ID; unique within pending same-qid_ questions of the same kind
    Index index_ = 0;
};

std::ostream &operator <<(std::ostream &, const RequestId &);

} // namespace Ipc;

#endif /* SQUID_IPC_REQUESTID_H */

