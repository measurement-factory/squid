/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "StrandKid.cc"
#include "tests/STUB.h"

#include "sbuf/SBuf.h"

#include "StrandKid.h"
void InitStrand() STUB
void TagStrand(const SBuf &) STUB
void StrandBarrierWait(const AsyncCallPointer &) STUB
void NotifyCoordinator(Ipc::MessageType, const std::optional<SBuf> &) STUB

