/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STRANDKID_H
#define SQUID_SRC_STRANDKID_H

#include "base/forward.h"
#include "sbuf/forward.h"

// XXX: Revise descriptions

/// Initiates this kid process registration with Coordinator as well as
/// listening for IPC messages from Coordinator. Repeated calls are safe and
/// do nothing.
/// \prec This process is an SMP Squid kid process but is not a Coordinator.
/// \sa InitTagged()
void InitStrand();

/// Same as Init() but supports "tagging" this strand so that other kids can
/// find it by that tag. Multiple calls must supply the same tag. If Init()
/// and InitTagged() calls are mixed, the first one must be InitTagged().
void TagStrand(const SBuf &);

/// Starts waiting for all kids to reach a startup synchronization barrier
/// maintained by Coordinator. When they do, calls the given callback.
void StrandBarrierWait(const AsyncCallPointer &);

#endif /* SQUID_SRC_STRANDKID_H */

