/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_QUESTION_ID_H
#define SQUID_IPC_QUESTION_ID_H

#include "ipc/forward.h"

namespace Ipc
{

/// Identifies a kid process sending IPC messages that require an answer.
/// Must be unique across all kids with pending questions.
class QuestionerId
{
public:
    /// \param init whether we should initialize the Id
    /// it is true for creators and false for recivers/responses 
    explicit QuestionerId(bool init);

    /// for receiving the ID of the asking process in questions and answers
    explicit QuestionerId(const TypedMsgHdr &);

    /// can copy the received ID of the asking process into an answer
    QuestionerId(const QuestionerId &) = default;

    /// for sending the ID of the asking process in questions and answers
    void pack(TypedMsgHdr &) const;

    /// for receiving the ID of the asking process in answers
    void unpack(const TypedMsgHdr &);

    /// does nothing but throws if the questioner was not the current process
    void rejectAnswerIfStale() const;

    std::ostream &print(std::ostream &os) const {
        os << pid;
        return os;
    }

private:
    /// OS process ID of the asking kid. If the kid restarts, it is assumed
    /// not to wrap back to the old value until the answer is received.
    pid_t pid;
};

/// Convenience wrapper for rejecting (freshly parsed) stale answers.
/// All answers are assumed to have a public "QuestionerId qid" member.
template <class Message>
const Message &Mine(const Message &message)
{
    message.qid.rejectAnswerIfStale();
    return message;
}

inline
std::ostream& operator << (std::ostream &os, const QuestionerId& qid)
{
    return qid.print(os);
}

} // namespace Ipc;

#endif /* SQUID_IPC_QUESTION_ID_H */

