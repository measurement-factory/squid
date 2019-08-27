/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ASYNC_CONTEXT_H
#define SQUID_SRC_ASYNC_CONTEXT_H

#include <string>

class AsyncContext
{
    public:
        virtual std::string context() const { return CurrentContext; }
        static void Reset(const char *context = nullptr);
        static const char *ToString() { return CurrentContext.empty() ? "-" : CurrentContext.c_str(); }
        void remember() { savedContext = context(); } 
        void recollect() { CurrentContext = savedContext; }

        std::string savedContext;
        static std::string CurrentContext;
};

#endif

