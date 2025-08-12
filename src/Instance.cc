/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/AsyncCall.h"
#include "base/AsyncFunCalls.h"
#include "base/File.h"
#include "debug/Messages.h"
#include "fs_io.h"
#include "Instance.h"
#include "ipc/Messages.h"
#include "ipc/StrandCoord.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "tools.h"

#include <cerrno>

#if HAVE_SYSTEMD_SD_DAEMON_H
#include <systemd/sd-daemon.h>
#endif

namespace Instance {
    static void StartupActivityStarted(const ScopedId &);
    static void StartupActivityFinished(const ScopedId &);
    static void StartupNotificationCheckpoint();
    static void StartupNotificationDelayedCheckpoint();
    static void AnnounceReadiness();
} // namespace Instance

/* To support concurrent PID files, convert local statics into PidFile class */

/// Describes the (last) instance PID file being processed.
/// This hack shortens reporting code while keeping its messages consistent.
static SBuf TheFile;

/// PidFilename() helper
/// \returns PID file name or, if PID signaling was disabled, an empty SBuf
static SBuf
PidFilenameCalc()
{
    if (!Config.pidFilename || strcmp(Config.pidFilename, "none") == 0)
        return SBuf();

    // If chroot has been requested, then we first read the PID file before
    // chroot() and then create/update it inside a chrooted environment.
    // TODO: Consider removing half-baked chroot support from Squid.
    extern bool Chrooted;
    if (!Config.chroot_dir || Chrooted) // no need to compensate
        return SBuf(Config.pidFilename);

    SBuf filename;
    filename.append(Config.chroot_dir);
    filename.append("/");
    filename.append(Config.pidFilename);
    debugs(50, 3, "outside chroot: " << filename);
    return filename;
}

/// \returns PID file description for debugging messages and error reporting
static SBuf
PidFileDescription(const SBuf &filename)
{
    return ToSBuf("PID file (", filename, ')');
}

/// Instance entry points are expected to call this first.
/// \returns PidFilenameCalc() result while updating TheFile context
static SBuf
PidFilename()
{
    const auto name = PidFilenameCalc();
    TheFile = PidFileDescription(name);
    return name;
}

/// \returns the PID of another Squid instance (or throws)
static pid_t
GetOtherPid(File &pidFile)
{
    const auto input = pidFile.readSmall(1, 32);
    int64_t rawPid = -1;

    Parser::Tokenizer tok(input);
    if (!(tok.int64(rawPid, 10, false) && // PID digits
            (tok.skipOne(CharacterSet::CR)||true) && // optional CR (Windows/etc.)
            tok.skipOne(CharacterSet::LF) && // required end of line
            tok.atEnd())) { // no trailing garbage
        throw TexcHere(ToSBuf("Malformed ", TheFile));
    }

    debugs(50, 7, "found PID " << rawPid << " in " << TheFile);

    if (rawPid <= 1)
        throw TexcHere(ToSBuf("Bad ", TheFile, " contains unreasonably small PID value: ", rawPid));
    const auto finalPid = static_cast<pid_t>(rawPid);
    if (static_cast<int64_t>(finalPid) != rawPid)
        throw TexcHere(ToSBuf("Bad ", TheFile, " contains unreasonably large PID value: ", rawPid));

    return finalPid;
}

/// determines whether a given process is running at the time of the call
static bool
ProcessIsRunning(const pid_t pid)
{
    const auto result = kill(pid, 0);
    const auto savedErrno = errno;
    if (result != 0)
        debugs(50, 3, "kill(" << pid << ", 0) failed: " << xstrerr(savedErrno));
    // if we do not have permissions to signal the process, then it is running
    return (result == 0 || savedErrno == EPERM);
}

/// quits if another Squid instance (that owns the given PID file) is running
static void
ThrowIfAlreadyRunningWith(File &pidFile)
{
    bool running = false;
    SBuf description;
    try {
        const auto pid = GetOtherPid(pidFile);
        description = ToSBuf(TheFile, " with PID ", pid);
        running = ProcessIsRunning(pid);
    }
    catch (const std::exception &ex) {
        debugs(50, 5, "assuming no other Squid instance: " << ex.what());
        return;
    }

    if (running)
        throw TexcHere(ToSBuf("Squid is already running: Found fresh instance ", description));

    debugs(50, 5, "assuming stale instance " << description);
}

pid_t
Instance::Other()
{
    const auto filename = PidFilename();
    if (filename.isEmpty())
        throw TexcHere("no pid_filename configured");

    File pidFile(filename, File::Be::ReadOnly().locked());
    return GetOtherPid(pidFile);
}

void
Instance::ThrowIfAlreadyRunning()
{
    const auto filename = PidFilename();
    if (filename.isEmpty())
        return; // the check is impossible

    if (const auto filePtr = File::Optional(filename, File::Be::ReadOnly().locked())) {
        const std::unique_ptr<File> pidFile(filePtr);
        ThrowIfAlreadyRunningWith(*pidFile);
    } else {
        // It is best to assume then to check because checking without a lock
        // might lead to false positives that lead to no Squid starting at all!
        debugs(50, 5, "cannot lock " << TheFile << "; assuming no other Squid is running");
        // If our assumption is false, we will fail to _create_ the PID file,
        // and, hence, will not start, allowing that other Squid to run.
    }
}

/// ties Instance::WriteOurPid() scheduler and RemoveInstance(void) handler
static SBuf ThePidFileToRemove;

/// atexit() handler; removes the PID file created with Instance::WriteOurPid()
static void
RemoveInstance()
{
    if (ThePidFileToRemove.isEmpty()) // not the PidFilename()!
        return; // nothing to do

    debugs(50, Important(22), "Removing " << PidFileDescription(ThePidFileToRemove));

    // Do not write to cache_log after our PID file is removed because another
    // instance may already be logging there. Stop logging now because, if we
    // wait until safeunlink(), some debugs() may slip through into the now
    // "unlocked" cache_log, especially if we avoid the sensitive suid() area.
    // Use stderr to capture late debugs() that did not make it into cache_log.
    Debug::StopCacheLogUse();

    const char *filename = ThePidFileToRemove.c_str(); // avoid complex operations inside enter_suid()
    enter_suid();
    safeunlink(filename, 0);
    leave_suid();

    ThePidFileToRemove.clear();
}

/// creates a PID file; throws on error
void
Instance::WriteOurPid()
{
    // Instance code assumes that we do not support PID filename reconfiguration
    static bool called = false;
    Must(!called);
    called = true;

    const auto filename = PidFilename();
    if (filename.isEmpty())
        return; // nothing to do

    File pidFile(filename, File::Be::ReadWrite().locked().createdIfMissing().openedByRoot());

    // another instance may have started after the caller checked (if it did)
    ThrowIfAlreadyRunningWith(pidFile);

    /* now we know that we own the PID file created and/or locked above */

    // Cleanup is scheduled through atexit() to ensure both:
    // - cleanup upon fatal() and similar "unplanned" exits and
    // - enter_suid() existence and proper logging support during cleanup.
    // Even without PID filename reconfiguration support, we have to remember
    // the file name we have used because Config.pidFilename may change!
    (void)std::atexit(&RemoveInstance); // failures leave the PID file on disk
    ThePidFileToRemove = filename;

    /* write our PID to the locked file */
    SBuf pidBuf;
    pidBuf.Printf("%d\n", static_cast<int>(getpid()));
    pidFile.truncate();
    pidFile.writeAll(pidBuf);

    // We must fsync before releasing the lock or other Squid processes may not see
    // our written PID (and decide that they are dealing with a corrupted PID file).
    pidFile.synchronize();

    debugs(50, Important(23), "Created " << TheFile);
}

// XXX: No new globals
static uint64_t StartedStartupActivities = 0;
static size_t RunningStartupActivities = 0;
static AsyncCall::Pointer TheRequestor;
static AsyncCall::Pointer TheDelayedCheckpoint;
static bool StartupEnded = false;

bool
Instance::Starting()
{
    return !StartupEnded;
}

/// Reacts to the beginning of the identified startup activity.
/// \sa Instance::StartupActivityFinished()
void
Instance::StartupActivityStarted(const ScopedId &id)
{
    Assure(id);
    ++StartedStartupActivities;
    ++RunningStartupActivities;
    Assure(RunningStartupActivities > 0); // no overflows
    debugs(50, 3, id << "; activities now: " << RunningStartupActivities << '/' << StartedStartupActivities);
    Assure(Starting());

    // We could remember activity ID, allowing StartupActivityFinished() to
    // check for matches, but all public APIs reliably use the same ID for both
    // calls, making such checks excessive.

    // TODO: Consider limiting startup by a timeout (scheduled here when StartedStartupActivities is 1).
}

/// Reacts to the end of the identified startup activity.
/// \sa Instance::StartupActivityStarted()
void
Instance::StartupActivityFinished(const ScopedId &id)
{
    Assure(id);
    Assure(RunningStartupActivities > 0);
    --RunningStartupActivities;
    debugs(50, 3, id << "; activities now: " << RunningStartupActivities << '/' << StartedStartupActivities);
    StartupNotificationCheckpoint();
}

void
Instance::NotifyWhenStartedStartupActivitiesFinished(const AsyncCallPointer &requestor)
{
    debugs(50, 3, "activities now: " << RunningStartupActivities);
    Assure(requestor);
    Assure(!TheRequestor);
    TheRequestor = requestor;
    StartupNotificationCheckpoint();
}

/// Starts reacting to NotifyWhenStartedStartupActivitiesFinished() callback
/// registration or RunningStartupActivities decrease. If possible, advances
/// towards that callback scheduling or an AnnounceReadiness() call.
/// \sa StartupNotificationDelayedCheckpoint().
static void
Instance::StartupNotificationCheckpoint()
{
    debugs(1, 7, "activities now: " << RunningStartupActivities);
    if (RunningStartupActivities)
        return; // wait for the still-running startup activities to finish

    // Wait for firing of any "begin startup activity X" async calls scheduled
    // by our (indirect) caller just before calling an Instance function. They
    // may schedule more calls (and then trigger another checkpoint); we must
    // reschedule our "wait for scheduled calls" check to also wait for those.
    if (TheDelayedCheckpoint)
        TheDelayedCheckpoint->cancel("rescheduling to cover any newly scheduled calls");
    using Dialer = NullaryFunDialer;
    TheDelayedCheckpoint = asyncCall(1, 3, "Instance::StartupNotificationDelayedCheckpoint",
                                     Dialer(&Instance::StartupNotificationDelayedCheckpoint));
    ScheduleCallHere(TheDelayedCheckpoint);
}

/// Completes processing started by StartupNotificationDelayedCheckpoint().
static void
Instance::StartupNotificationDelayedCheckpoint()
{
    TheDelayedCheckpoint = nullptr;

    if (RunningStartupActivities) {
        // some startup activity was started when asynchronous calls scheduled
        // by the previously finished startup activity were fired
        debugs(1, 5, "waiting for recently started activities: " << RunningStartupActivities);
        return;
    }

    if (TheRequestor) {
        debugs(1, 7, "informing " << TheRequestor->id);
        ScheduleCallHere(TheRequestor);
        TheRequestor = nullptr;
        StartupNotificationCheckpoint(); // TheRequestor may start more startup activities
        return;
    }

    debugs(1, 3, "all startup activities have ended and no new ones are expected");
    Assure(Starting());
    Assure(!StartupEnded);
    StartupEnded = true;
    Assure(!Starting());

    if (UsingSmp() && !IamCoordinatorProcess())
        Ipc::StrandMessage::NotifyCoordinator(Ipc::mtKidCompletedStartup, nullptr);
    else
        Instance::AnnounceReadiness();
}

/// informs systemd that this instance has completed its startup sequence (where supported)
static void
Instance::AnnounceReadiness()
{
    debugs(1, 2, "all Squid processes are ready");
#if USE_SYSTEMD
    if (opt_foreground || opt_no_daemon) {
        const auto result = sd_notify(1, "READY=1");
        if (result < 0) {
            debugs(1, DBG_IMPORTANT, "WARNING: failed to send start-up notification to systemd" <<
                   Debug::Extra << "sd_notify() error: " << xstrerr(-result));
        }
    }
#endif
}

/* Instance::StartupActivityTracker */

Instance::StartupActivityTracker::StartupActivityTracker(const ScopedId &id): id_(id)
{
    StartupActivityStarted(id_);
}

Instance::StartupActivityTracker::~StartupActivityTracker()
{
    if (id_)
        StartupActivityFinished(id_);
}

Instance::StartupActivityTracker::StartupActivityTracker(StartupActivityTracker &&other)
{
    std::swap(id_, other.id_);
}

/* Instance::OptionalStartupActivityTracker */

void
Instance::OptionalStartupActivityTracker::started(const ScopedId &id)
{
    Assure(!started_);
    Assure(!finished_);
    started_ = true;

    Assure(!tracker_);
    tracker_.emplace(id);
}

void
Instance::OptionalStartupActivityTracker::finished()
{
    Assure(started_);
    Assure(!finished_);
    finished_ = true;

    Assure(tracker_);
    tracker_ = std::nullopt;
}

