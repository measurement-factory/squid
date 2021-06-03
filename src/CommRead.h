/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Comm */

#ifndef COMMREAD_H
#define COMMREAD_H

#include "base/forward.h"

#include <vector>

// TODO: create dedicated header/source files
/// maintains a list of async calls and schedules them at once
class DeferredReadManager
{
public:
    ~DeferredReadManager() { kickReads(); }
    /// stores an async call in a list
    void delayRead(const AsyncCallPointer &);
    /// schedules all previously stored async calls and clears the list
    void kickReads();

private:
    std::vector<AsyncCallPointer> deferredReads;
};

#endif /* COMMREAD_H */

