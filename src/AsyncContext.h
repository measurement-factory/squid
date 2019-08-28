/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ASYNC_CONTEXT_H
#define SQUID_SRC_ASYNC_CONTEXT_H

#include "http/forward.h"

class AsyncContext : public RefCountable
{
    public:
        AsyncContext();
        AsyncContext(const HttpRequestPointer &);
        ~AsyncContext();

        AsyncContext(const AsyncContext &) = delete;
        AsyncContext &operator=(const AsyncContext &) = delete;

        void restore();

        HttpRequestPointer *request;
};

typedef RefCount<AsyncContext> AsyncContextPointer;

#endif

