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
#include "base/InstanceId.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/// code related to Squid Instance and PID file management
namespace Instance {

/// Tracks a task performed as a part of Squid startup sequence. These tasks
/// start before (and are independent from) client-initiated transactions. They
/// need to be tracked to enforce relationships among startup tracks and to know
/// when all startup activities have finished, signaling the end of startup.
class StartupActivityTracker
{
public:
    /// configures the activity without starting it
    explicit StartupActivityTracker(const ScopedId &id);

    /// Called at the beginning of a tracked activity.
    /// \prec started() has not been called earlier
    /// \prec finished() has not been called earlier
    void started();

    /// Called at the end of a started() tracked activity.
    /// \prec started() has been called earlier
    /// \prec finished() has not been called earlier
    void finished();

private:
    ScopedId id_;
    bool started_ = false; ///< started() has been called
    bool finished_ = false; ///< finished() has been called
};

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

