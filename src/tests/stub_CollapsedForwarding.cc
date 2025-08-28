/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CollapsedForwarding.h"
#include "MemObject.h"
#include "Store.h"

#define STUB_API "CollapsedForwarding.cc"
#include "tests/STUB.h"

void CollapsedForwarding::Broadcast(const StoreEntry &e, const SourceLocation &, bool)
{
    // an assertion in StoreEntry::noteChangesToBroadcast() requires this
    if (e.mem_obj)
        e.mem_obj->sawChangesToBroadcast = false; // may already be false

    // Store unit tests do tickle Broadcast()-related code, but they do not test
    // SMP configurations that would require it to work, so we use STUB_NOPs.
    STUB_NOP
}

void CollapsedForwarding::Broadcast(sfileno, const SourceLocation &, bool) STUB_NOP
void CollapsedForwarding::StatQueue(std::ostream &) STUB

Store::BroadcastMonitor::BroadcastMonitor(StoreEntry &e): entry(e) { STUB_NOP }
Store::BroadcastMonitor::~BroadcastMonitor() STUB_NOP
