/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FS_ROCK_ROCKIOREQUESTS_H
#define SQUID_SRC_FS_ROCK_ROCKIOREQUESTS_H

#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/forward.h"
#include "fs/rock/RockIoState.h"

#include <optional>

class DiskFile;

namespace Rock
{

class ReadRequest: public ::ReadRequest
{
    CBDATA_CLASS(ReadRequest);

public:
    ReadRequest(const ::ReadRequest &, const IoState::Pointer &, const IoXactionId);
    IoState::Pointer sio;

    /// identifies this read transaction for the requesting IoState
    IoXactionId id;
};

class WriteRequest: public ::WriteRequest
{
    CBDATA_CLASS(WriteRequest);

public:
    WriteRequest(const ::WriteRequest &, const IoState::Pointer &, const IoXactionId);
    IoState::Pointer sio;

    /* We own these two reserved slots until SwapDir links them into the map. */

    /// slot that will point to sidCurrent in the cache_dir map
    SlotId sidPrevious;

    /// slot being written using this write request
    SlotId sidCurrent;

    /// identifies this write transaction for the requesting IoState
    IoXactionId id;

    /// whether this is the last request for the entry
    bool eof;
};

/// a request to write an empty DbCellHeader
class ZeroingRequest: public ::WriteRequest
{
    CBDATA_CLASS(ZeroingRequest);

public:
    using Pointer = RefCount<ZeroingRequest>;

    explicit ZeroingRequest(uint64_t diskOffset);

    /// whether the request succeeded (for processed requests)
    std::optional<bool> completed;
};

} // namespace Rock

#endif /* SQUID_SRC_FS_ROCK_ROCKIOREQUESTS_H */

