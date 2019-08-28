/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AsyncContext.h"
#include "AsyncContextManager.h"
#include "HttpRequest.h"
#include "sbuf/SBuf.h"

AsyncContext::AsyncContext(const HttpRequestPointer &req) : request(new HttpRequestPointer)
{
    *request = req;
}

AsyncContext::AsyncContext() : request(new HttpRequestPointer)
{}

AsyncContext::~AsyncContext()
{
    delete request;
}

void
AsyncContext::restore()
{
    AsyncContextManager::Instance().reset(this);
    // should we clean the local context?
    // *request = HttpRequestPointer();
}

