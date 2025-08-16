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
#include "ipc/Messages.h"
#include "sbuf/forward.h"

#include <optional>

/// Initiates this kid process registration with Coordinator as well as
/// listening for IPC messages from Coordinator. Repeated calls are safe and
/// do nothing.
/// \prec This process is an SMP Squid kid process but is not a Coordinator.
/// \sa TagStrand()
void InitStrand();

/// Annotates this kid process so that other kids can find it by the given tag.
/// Multiple calls must supply the same tag.
/// \prec InitStrand() has not been called
/// \prec This process is an SMP Squid kid process but is not a Coordinator.
void TagStrand(const SBuf &);

/// Starts waiting for all kids to reach a startup synchronization barrier
/// maintained by Coordinator. When they do, calls the given callback.
/// \prec This process is an SMP Squid kid process but is not a Coordinator.
void StrandBarrierWait(const AsyncCallPointer &);

/// Sends the corresponding IPC message (optionally, with a strand tag) to Coordinator
/// \prec This process is an SMP Squid kid process but is not a Coordinator.
void NotifyCoordinator(Ipc::MessageType, const std::optional<SBuf> &tag = std::nullopt);

#endif /* SQUID_SRC_STRANDKID_H */

