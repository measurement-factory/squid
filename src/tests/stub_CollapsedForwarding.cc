/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CollapsedForwarding.h"

#define STUB_API "CollapsedForwarding.cc"
#include "tests/STUB.h"

void CollapsedForwarding::Broadcast(const StoreEntry &, const SourceLocation &, bool) STUB
void CollapsedForwarding::Broadcast(sfileno, const SourceLocation &, bool) STUB
void CollapsedForwarding::StatQueue(std::ostream &) STUB

Store::BroadcastMonitor::BroadcastMonitor(StoreEntry &e): entry(e) { STUB }
Store::BroadcastMonitor::~BroadcastMonitor() STUB
