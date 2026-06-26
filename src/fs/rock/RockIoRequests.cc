/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "fs/rock/RockIoRequests.h"

CBDATA_NAMESPACED_CLASS_INIT(Rock, ReadRequest);
CBDATA_NAMESPACED_CLASS_INIT(Rock, WriteRequest);
CBDATA_NAMESPACED_CLASS_INIT(Rock, ZeroingRequest);

Rock::ReadRequest::ReadRequest(const ::ReadRequest &base, const IoState::Pointer &anSio, const IoXactionId anId):
    ::ReadRequest(base),
    sio(anSio),
    id(anId)
{
}

Rock::WriteRequest::WriteRequest(const ::WriteRequest &base, const IoState::Pointer &anSio, const IoXactionId anId):
    ::WriteRequest(base),
    sio(anSio),
    sidPrevious(-1),
    sidCurrent(-1),
    id(anId),
    eof(false)
{
}

/// ZeroingRequest construction helper that creates a DbCellHeader with true empty()
static
const auto &
EmptyCellHeader()
{
    static const auto emtyCell = new Rock::DbCellHeader();
    return *emtyCell;
}

Rock::ZeroingRequest::ZeroingRequest(const uint64_t diskOffset):
    ::WriteRequest(reinterpret_cast<const char*>(&EmptyCellHeader()),
                   diskOffset, sizeof(EmptyCellHeader()), nullptr)
{
    // Paranoid: Base class initialization above uses the fact that
    // sizeof(reference to x) is sizeof(x).
    static_assert(sizeof(EmptyCellHeader()) == sizeof(Rock::DbCellHeader));
}

