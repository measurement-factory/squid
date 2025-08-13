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

#include <optional>

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/// code related to Squid Instance and PID file management
namespace Instance {

/// Automatically tracks a task performed as a part of Squid startup sequence.
/// These tasks start before (and are independent from) client-initiated
/// transactions. They need to be tracked to enforce relationships among startup
/// tracks and to know when all startup activities have finished, signaling the
/// end of startup.
class StartupActivityTracker
{
public:
    /// starts tracking the identified activity
    explicit StartupActivityTracker(const ScopedId &id);

    /// finishes tracking the previously identified activity (if still responsible for it)
    ~StartupActivityTracker();

    /// moves tracking responsibility without starting or finishing any activities
    StartupActivityTracker(StartupActivityTracker &&);

    /* prohibit copying to ensure single tracker for each activity */
    StartupActivityTracker(const StartupActivityTracker &) = delete;
    StartupActivityTracker &operator =(StartupActivityTracker &) = delete;
    /* prohibit moving assignment to avoid surprising end to old activity tracking */
    StartupActivityTracker &operator =(StartupActivityTracker &&) = delete;

private:
    ScopedId id_; ///< identifies a running activity (from start to finish)
};

/// An std::optional<StartupActivityTracker> wrapper for a common use case of a
/// startup activity that starts some time after its owner has been created or
/// finishes before its owner is being destructed
class OptionalStartupActivityTracker
{
public:
    /// whether both start() and finish() have been called OR, since finish()
    /// requires start(), whether finish() has been called
    bool startedAndFinished() const { return started_ && finished_; }

    /// Initiates tracking at the beginning of a tracked activity.
    /// \prec start() has not been called earlier
    /// \prec finish() has not been called earlier
    void start(const ScopedId &);

    /// Terminates tracking at the end of a tracked activity.
    /// \prec start() has been called earlier
    /// \prec finish() has not been called earlier
    void finish();

private:
    /// started but not yet finished activity tracker
    std::optional<StartupActivityTracker> tracker_;

    bool started_ = false; ///< start() has been called
    bool finished_ = false; ///< finish() has been called
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

/// Schedules the given callback when the number of running startup activities
/// goes to zero. That event does not imply the end of startup because the
/// callback may launch new startup activities; it only implies that all
/// caller's startup prerequisites have been satisfied.
///
/// Repeated calls are supported, but awaiting multiple notifications at the
/// same time is not. In other words, the next call to this function must not
/// happen before the callback from the previous call has been scheduled.
///
/// \sa Starting()
void NotifyWhenStartedStartupActivitiesFinished(const AsyncCallPointer &);

/// Whether this process may launch a new startup activity.
///
/// The startup period begins with the process execution and ends shortly after
/// the very last StartupActivityTracker is gone. To automatically detect the
/// latter event, we assume that any startup activity except the very first one
/// is only launched during other startup activities (i.e. a new startup
/// activity may not launch spontaneously, after all previous activities end).
/// Startup activities that schedule launches using AsyncCalls are supported.
///
/// \retval false after startup period completion, including during reconfiguration
bool Starting();

} // namespace Instance

#endif

