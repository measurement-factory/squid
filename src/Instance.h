/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_INSTANCE_H
#define SQUID_INSTANCE_H

#include "base/forward.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/// code related to Squid Instance and PID file management
namespace Instance {

/// Usually throws if another Squid instance is running. False positives are
/// highly unlikely, but the caller must tolerate false negatives well:
/// We may not detect another running instance and, hence, may not throw.
/// Does nothing if PID file maintenance is disabled.
void ThrowIfAlreadyRunning();

/// Creates or updates the PID file for the current process.
/// Does nothing if PID file maintenance is disabled.
void WriteOurPid();

/// \returns another Squid instance PID
/// Throws if PID file maintenance is disabled.
pid_t Other();

/// XXX: Describe!
void StartupActivityStarted(const ScopedId &);
void StartupActivityFinished(const ScopedId &);
void NotifyWhenStartedStartupActivitiesFinished(const AsyncCallPointer &requestor);

/// Whether this process may launch a new startup activity.
///
/// The startup period begins with the process execution and ends shortly after
/// the very last StartupActivityFinished() call. To automatically detect the
/// latter event, we assume that any startup activity except the very first one
/// is only launched during other startup activities (i.e. a new startup
/// activity may not launch spontaneously, after all previous activities end).
/// Startup activities that schedule launches using AsyncCalls are supported.
///
/// \retval false after startup period completion, including during reconfiguration
bool Starting();


} // namespace Instance

#endif

