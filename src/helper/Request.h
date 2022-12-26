/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HELPER_REQUEST_H
#define _SQUID_SRC_HELPER_REQUEST_H

#include "helper/forward.h"
#include "time/gadgets.h"

namespace Helper
{

class Request
{
    MEMPROXY_CLASS(Helper::Request);

public:
    Request(HLPCB *c, void *d, const char *b) :
        buf(b ? xstrdup(b) : nullptr),
        data(cbdataReference(d)),
        placeholder(b == nullptr),
        Id(0),
        retries(0),
        callback_(c)
    {
        memset(&dispatch_time, 0, sizeof(dispatch_time));
    }

    ~Request() {
        cbdataReferenceDone(data);
        xfree(buf);
    }

    /// Forward helper response (or its equivalent) to the requestor. XXX: The
    /// caller must check the cbdataReferenceValid() precondition. TODO: Move
    /// that checking code into this method by refactoring callers.
    void callback(void * const validatedCbdata, const Reply &reply) {
        // TODO: Move to a src/helper/Request.cc.

        assert(callback_);

        // TODO: Warn about unused recognized annotations:
        // reply.notes.checkForUnused();

        const auto cb = callback_;
        callback_ = nullptr;
        cb(validatedCbdata, reply);
    }

    char *buf;
    void *data;

    int placeholder;            /* if 1, this is a dummy request waiting for a stateful helper to become available */
    struct timeval dispatch_time;
    uint64_t Id;
    /**
     * A helper may configured to retry timed out requests or on BH replies.
     * We attempt to recover by trying the lookup again, but limit the
     * number of retries to prevent lag and lockups.
     * This tracks the number of previous failures for the request.
     */
    int retries;
    bool timedOut(time_t timeout) {return (squid_curtime - dispatch_time.tv_sec) > timeout;}

private:
    HLPCB *callback_; ///< where to send the final outcome of helper transaction(s)
};

} // namespace Helper

#endif /* _SQUID_SRC_HELPER_REQUEST_H */

