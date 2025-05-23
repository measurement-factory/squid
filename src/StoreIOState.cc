/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Swap Dir base object */

#include "squid.h"
#include "debug/Stream.h"
#include "defines.h"
#include "Store.h"
#include "StoreIOState.h"

void *
StoreIOState::operator new (size_t)
{
    assert(0);
    return (void *)1;
}

void
StoreIOState::operator delete (void *)
{
    assert(0);
}

StoreIOState::StoreIOState(StoreIOState::STIOCB *cbIo, void *data) :
    swap_dirn(-1),
    swap_filen(-1),
    e(nullptr),
    mode(O_BINARY),
    offset_(0),
    callback(cbIo),
    callback_data(cbdataReference(data))
{
    read.callback = nullptr;
    read.callback_data = nullptr;
    flags.closing = false;
}

StoreIOState::~StoreIOState()
{
    debugs(20,3, "StoreIOState::~StoreIOState: " << this);

    cbdataReferenceDone(read.callback_data);
    cbdataReferenceDone(callback_data);
}

bool StoreIOState::touchingStoreEntry() const
{
    return e && e->swap_filen == swap_filen;
}

