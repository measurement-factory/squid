/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_TRAITS_H
#define SQUID_SRC_BASE_TRAITS_H

class PooledByChildren
{
    public:
        /// Derived classes are expected to pool dynamic memory allocations.
        void *operator new(size_t) = delete;
};

#endif /* SQUID_SRC_BASE_TRAITS_H */

