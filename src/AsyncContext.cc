/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "AsyncContext.h"

std::string AsyncContext::CurrentContext;

void
AsyncContext::Reset(const char *context)
{
    if (context)
        CurrentContext.assign(context);
    else
        CurrentContext.clear();
}

