/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

int snprintfXXX(char *str, size_t size, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const auto result = snprintf(str, size, fmt, args);
    va_end(args);
    return result;
}

