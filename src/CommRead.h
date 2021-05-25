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

#include "base/CbDataList.h"
#include "comm.h"
#include "comm/forward.h"
#include "CommCalls.h"

class DeferredReadManager
{

public:
    ~DeferredReadManager();
    void delayRead(const AsyncCall::Pointer &);
    void kickReads();

private:
    std::vector<AsyncCall::Pointer> deferredReads;
};

#endif /* COMMREAD_H */

