/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#include "squid.h"
#include "Debug.h"
#include "fd.h"
#include "ipc/Kids.h"
#include "SquidTime.h"
#include "util.h"

#include <algorithm>

/* for shutting_down flag in xassert() */
#include "globals.h"

char *Debug::debugOptions = NULL;
int Debug::override_X = 0;
bool Debug::log_syslog = false;
int Debug::Levels[MAX_DEBUG_SECTIONS];
char *Debug::cache_log = NULL;
int Debug::rotateNumber = -1;

class DebugModule;
/// Debugging module singleton.
static DebugModule *Module_ = nullptr;

/// a cached calculateMyLeadingRole() result
extern const char *XXX_Role;
const char *XXX_Role = nullptr;

/// debugs() messages with this (or lower) level will be written to stderr
/// (and possibly other channels). Negative values disable stderr logging.
/// This restriction is ignored if Squid tries but fails to open cache.log.
static int MaxErrLogLevel = -1;

/// MaxErrLogLevel default; ignored after FinalizeErrLogLevel()
static int MaxErrLogLevelDefault = -1;

static const char *debugLogTime(void);
static const char *debugLogKid(void);
#if HAVE_SYSLOG
#ifdef LOG_LOCAL4
static int syslog_facility = 0;
#endif
#endif

#if _SQUID_WINDOWS_
extern LPCRITICAL_SECTION dbg_mutex;
typedef BOOL (WINAPI * PFInitializeCriticalSectionAndSpinCount) (LPCRITICAL_SECTION, DWORD);
#endif

static void ResetSections(const int level = DBG_IMPORTANT);

/// early debugs() with higher level are not buffered and, hence, may be lost
static constexpr int EarlyMessagesMaxLevel = DBG_IMPORTANT;

/// used for the side effect: fills Debug::Levels with the given level
static void
ResetSections(const int level)
{
    for (auto i = 0; i < MAX_DEBUG_SECTIONS; ++i)
        Debug::Levels[i] = level;
}

/// a (FILE*, file name) pair
class DebugFile
{
public:
    DebugFile() {}
    ~DebugFile() { clear(); }
    DebugFile(DebugFile &&) = delete; // no copying or moving of any kind

    /// switches to the new pair, absorbing FILE and duping the name
    void reset(FILE *newFile, const char *newName);

    /// go back to the initial state
    void clear() { reset(nullptr, nullptr); }

    ///< could not open "real" file due to an error
    void fail();

    bool failed() { return failed_; }

    /// logging stream
    FILE *file() { return file_; }

    char *name = nullptr;

private:
    friend void ResyncDebugLog(FILE *newFile);

    FILE *file_ = nullptr; ///< opened "real" file or nil; never stderr

    bool failed_ = false; ///< whether fail() was called
};

/// a stored debugs() message
class DebugMessage
{
public:
    DebugMessage(int section, int level, bool forceAlert, const char *prefix, const std::string &suffix);

    int section; ///< the debug section
    int level; ///< the debug level
    bool forceAlert; ///< the debugs() forceAlert flag
    std::string prefix; ///< the beginning of the log line
    std::string suffix; ///< the log line after the prefix (without the newline)
};

// TODO: Rename to EarlyDebugMessages or some such because the class has code
// specific to handling early messages.
/// preserves (a limited amount of) debugs() messages for delayed logging
class DebugMessages
{
public:
    DebugMessages() = default;
    // no copying or moving or any kind (for simplicity sake and to prevent accidental copies)
    DebugMessages(DebugMessages &&) = delete;

    /// stores the given message (if possible) or forgets it (otherwise)
    void insert(int section, int level, bool forceAlert, const char *prefix, const std::string &suffix);

    /// prints message buffering statistics
    void report() const;

    auto raw() const { return messages; }

private:
    void dropAllToStderr();

    typedef std::vector<DebugMessage> Storage;
    Storage messages;

    /// the total number of messages we could not store (due to capacity limits)
    uint64_t dropped = 0;
};

/// a receiver of debugs() messages (e.g., stderr or cache.log)
class DebugChannel
{
public:
    explicit DebugChannel(const char * const aName): name(aName) {}
    virtual ~DebugChannel() {}

    // no copying or moving or any kind (for simplicity sake and to prevent accidental copies)
    DebugChannel(DebugChannel &&) = delete;

    /// maybeLog() all saved but not yet written "early" messages (if any).
    void flush();

    /// End early message buffering, flushing saved messages.
    /// Side effect: When no channel needs them, stops saving early messages.
    void stopEarlyMessageCollection();

    /// Log the message to the channel if the channel accepts (such) messages.
    /// Do nothing otherwise.
    virtual void maybeLog(const DebugMessage &) = 0;

public:
    const char * const name = nullptr; ///< unique channel label for debugging

    uint64_t logged = 0; ///< the number of messages logged so far
    bool flushed = false; ///< whether flush() has been called
};

/// cache_log DebugChannel
class CacheLogChannel: public DebugChannel
{
public:
    CacheLogChannel(): DebugChannel("cache_log") {}

    /// \copydoc DebugChannel::maybeLog()
    void maybeLog(const char *prefix, const std::string &suffix);

    /// Allow errLogChannel to take over (e.g., after cache_log failed to open)
    void switchToErrLog();

    /* DebugChannel API */

    virtual void maybeLog(const DebugMessage &m) final
    {
        maybeLog(m.prefix.c_str(), m.suffix);
    }
};

/// stderr DebugChannel
class ErrLogChannel: public DebugChannel
{
public:
    ErrLogChannel(): DebugChannel("errlog") {}

    /// \copydoc DebugChannel::maybeLog()
    void maybeLog(int level, const char *prefix, const std::string &suffix);

    /* DebugChannel API */

    virtual void maybeLog(const DebugMessage &m) final
    {
        maybeLog(m.level, m.prefix.c_str(), m.suffix);
    }

protected:
    friend void CacheLogChannel::switchToErrLog();

    void noteRejected(int level);

    /// Start to take care of past/saved and future cacheLogChannel messages.
    /// Assumes that its caller will checkEarlyMessageCollectionTermination().
    void takeOverCacheLog();

    /// logs all previously saved early messages
    void writeAllSaved();

private:
    /// whether maybeLog() refused to log any ShouldBeSaved() messages
    bool rejectedShouldBeSavedMessages = false;

    /// whether maybeLog()ing already saved early messages is prohibited
    bool rejectSavedMessages = false;
};

/// syslog DebugChannel
class SysLogChannel: public DebugChannel
{
public:
    SysLogChannel(): DebugChannel("syslog") {}

    /// \copydoc DebugChannel::maybeLog()
    void maybeLog(bool forceAlert, int level, const std::string &message);

    /* DebugChannel API */

    virtual void maybeLog(const DebugMessage &m) final
    {
        maybeLog(m.forceAlert, m.level, m.suffix);
    }
};

/// Manages private module state that must be available during program startup
/// and (especially) termination. Any non-trivial state objects must be
/// encapsulated here because debugs() may be called before dynamic
/// initialization or after the destruction of static objects in debug.cc.
class DebugModule
{
public:
    DebugModule();

    // we provide debugging services for the entire duration of the program
    ~DebugModule() = delete;

    /// \copydoc Debug::Flush()
    void flush();

    /// Stops saving early messages when all channels no longer need them.
    void checkEarlyMessageCollectionTermination();

    /// stores the given message (if possible) or forgets it (otherwise)
    void saveEarlyMessage(int section, int level, bool forceAlert, const char *prefix, const std::string &suffix);

public:
    CacheLogChannel cacheLogChannel;
    ErrLogChannel errLogChannel;
    SysLogChannel sysLogChannel;
};

/// Preserves important debugs() messages until the log file gets opened and
/// then logs those messages. Must be accessed via EarlyMessages() except for
/// assignment.
static DebugMessages *EarlyMessages = nullptr;

// Becomes true during C++ constant initialization, before any debugs() calls.
// Exists because EarlyMessages cannot be set during constant initialization.
/// whether "early" messages may need to be accumulated and/or logged
static bool SavingEarlyMessages = true;

/// configured cache.log file or stderr
/// safe during static initialization, even if it has not been constructed yet
static DebugFile TheLog;

static inline
int
ShouldBeSaved(const int level)
{
    return SavingEarlyMessages && level <= EarlyMessagesMaxLevel;
}

/* DebugModule */

// Depending on DBG_CRITICAL activity and command line options, this code may
// run as early as static initialization during program startup or as late as
// the first debugs(DBG_CRITICAL) call from the main loop.
DebugModule::DebugModule()
{
    // explicit initialization before any use by debugs() calls; see bug #2656
    tzset();

    (void)std::atexit(&Debug::Flush);

    if (!Debug::override_X)
        ResetSections();
}

void
DebugModule::checkEarlyMessageCollectionTermination()
{
    if (SavingEarlyMessages && cacheLogChannel.flushed && errLogChannel.flushed && sysLogChannel.flushed) {
        SavingEarlyMessages = false;
        if (EarlyMessages) {
            EarlyMessages->report();
            delete EarlyMessages;
            EarlyMessages = nullptr;
        }
    }
}

void
DebugModule::saveEarlyMessage(const int section, const int level, const bool forceAlert, const char * const prefix, const std::string &suffix)
{
    assert(SavingEarlyMessages);
    if (!EarlyMessages)
        EarlyMessages = new DebugMessages();
    EarlyMessages->insert(section, level, forceAlert, prefix, suffix);
}

void
DebugModule::flush()
{
    errLogChannel.flush();
    sysLogChannel.flush();
    cacheLogChannel.flush();
}

/// safe access to the debugging module
static
DebugModule &
Module() {
    if (!Module_) {
        Module_ = new DebugModule();
#if !defined(HAVE_SYSLOG)
        // Optimization: Do not wait for others to tell us what we already know.
        Debug::SettleSysLogging();
#endif
    }

    return *Module_;
}

FILE *
DebugStream() {
    return TheLog.file() ? TheLog.file() : stderr;
}

void
StopUsingDebugLog()
{
    TheLog.clear();
}

void
ResyncDebugLog(FILE *newFile)
{
    TheLog.file_ = newFile;
}

/* DebugChannel */

void
DebugChannel::flush()
{
    if (flushed)
        return;
    flushed = true;

    if (!EarlyMessages)
        return;

    for (const auto &message: EarlyMessages->raw()) {
        if (Debug::Enabled(message.section, message.level))
            maybeLog(message);
    }

    // Use debugs() level that prevents message buffering. Otherwise, this could
    // overflow the messages buffer, and dropAllToStderr() could dump the lines
    // we just reported above, possibly duplicating the lines on stderr.
    debugs(0, EarlyMessagesMaxLevel+1, "wrote " << logged << " out of " <<
           EarlyMessages->raw().size() << " early messages to " << name);
}

void
DebugChannel::stopEarlyMessageCollection()
{
    flush();
    Module().checkEarlyMessageCollectionTermination();
}

void
Debug::Flush()
{
    Module().flush();
}

/* CacheLogChannel */

void
CacheLogChannel::switchToErrLog()
{
    if (flushed)
        return;
    flushed = true;

    auto &module = Module();
    module.errLogChannel.takeOverCacheLog();
    module.checkEarlyMessageCollectionTermination();
}

void
CacheLogChannel::maybeLog(const char *prefix, const std::string &suffix)
{
    if (!flushed)
        return;

    if (!TheLog.file())
        return;

    fprintf(TheLog.file(), "role=%s # %s%s\n", XXX_Role, prefix, suffix.c_str());
    fflush(TheLog.file());
    ++logged;
}

/* ErrLogChannel */

void
ErrLogChannel::noteRejected(const int level)
{
    rejectedShouldBeSavedMessages = rejectedShouldBeSavedMessages || ShouldBeSaved(level);
}

void
ErrLogChannel::maybeLog(const int level, const char *prefix, const std::string &suffix)
{
    if (!stderr)
        return noteRejected(level);

    if (!Debug::ErrLogEnabled(level))
        return noteRejected(level);

    // Do not delay logging of immediately log-able messages. Some of them may
    // not be saveable.
    if (!flushed)
        flush(); // avoid reordering messages

    fprintf(stderr, "role=%s # %s%s\n", XXX_Role, prefix, suffix.c_str());
    ++logged;

    // If we logged anything after rejecting, then we cannot accept saved
    // messages because doing so will reorder logged messages.
    rejectSavedMessages = rejectedShouldBeSavedMessages; // may already be equal
}

void
ErrLogChannel::takeOverCacheLog()
{
    assert(!TheLog.file()); // we will allow future messages regardless of -dN

    // we are settled because we are taking over a settled cacheLogChannel
    flushed = true; // may already be true

    if (!rejectSavedMessages)
        return writeAllSaved(); // no danger of reordering messages on stderr

    // We have logged only some of the saved lines (e.g., -d0) and/or logged
    // some of the lines that follow the saved lines (e.g., -Xd2). To avoid
    // confusion, do not log duplicate and/or out-of-order lines.
    const auto saved = EarlyMessages ? EarlyMessages->raw().size() : 0;
    debugs(0, DBG_CRITICAL, "ERROR: Dropping " << saved << " early cache_log messages because " <<
           "stderr may have logged some of them (or some of the subsequent messages) already");
}

void
ErrLogChannel::writeAllSaved()
{
    assert(!rejectSavedMessages); // no conflicts with past messages
    assert(flushed); // no conflicts with messages that will be logged later

    // maybeLog will not reject saved messages
    assert(Debug::ErrLogEnabled(EarlyMessagesMaxLevel));

    if (!EarlyMessages)
        return; // nothing to write

    for (const auto &message: EarlyMessages->raw()) {
        if (Debug::Enabled(message.section, message.level))
            maybeLog(message);
    }
}

bool
Debug::ErrLogEnabled(const int level)
{
    if (!stderr)
        return false; // nowhere to log

    if (level <= MaxErrLogLevel)
        return true; // this level is allowed by our configuration: -d, -k, etc.

    // whether we are used as the last logging resort for cache.log messages
    // (higher-level callers have applied cache.log section/level filter)
    return TheLog.failed();
}

void
Debug::EnsureDefaultErrLogLevel(const int maxDefault)
{
    if (MaxErrLogLevelDefault < maxDefault)
        MaxErrLogLevelDefault = maxDefault; // may set or increase
    // else: somebody has already requested a more permissive maximum
}

void
Debug::ResetErrLogLevel(const int maxLevel)
{
    MaxErrLogLevel = maxLevel; // may set, increase, or decrease
}

void
Debug::SettleErrLogging()
{
    if (MaxErrLogLevel < 0)
        MaxErrLogLevel = MaxErrLogLevelDefault; // may remain disabled/negative

    Module().errLogChannel.stopEarlyMessageCollection();
}

/* DebugFile */

void DebugFile::fail()
{
    clear();
    failed_ = true;
}

void
DebugFile::reset(FILE *newFile, const char *newName)
{
    // callers must use nullptr instead of the used-as-the-last-resort stderr
    assert(newFile != stderr || !stderr);

    if (file_) {
        fd_close(fileno(file_));
        fclose(file_);
    }
    file_ = newFile; // may be nil

    if (file_)
        fd_open(fileno(file_), FD_LOG, Debug::cache_log);

    xfree(name);
    name = newName ? xstrdup(newName) : nullptr;

    // all open files must have a name
    // all cleared files must not have a name
    assert(!file_ == !name);
}

/// Works around the fact that IamWorkerProcess() and such lie until
/// command-line arguments are parsed.
static const char*
calculateMyLeadingRole()
{
    static bool Checked = false;
    assert(!Checked); // no recursion
    Checked = true;

    const auto fd = open("/proc/self/cmdline", O_RDONLY);
    assert(fd >= 0);
    char buf[128];
    const auto readBytes = read(fd, buf, sizeof(buf));
    assert(readBytes > 13);
    buf[readBytes-1] = '\0';

    if (buf[0] != '(')
        return "head"; // daemonized master overwrites in GoIntoBackground()

    if (strncmp(buf, "(squid-coord-", 13) == 0)
        return "coordinator";

    if (strncmp(buf, "(squid-disk-", 12) == 0)
        return "disker";

    if (strncmp(buf, "(squid-", 7) == 0)
        return "worker"; // XXX: did not check for a digit

    return "other";
}

static const char*
myLeadingRole()
{
    if (!XXX_Role) {
        XXX_Role = calculateMyLeadingRole();
        assert(XXX_Role);
    }
    return XXX_Role;
}

static
void
LogMessage(const bool forceAlert, const std::string &message)
{
#if _SQUID_WINDOWS_
    /* Multiple WIN32 threads may call this simultaneously */

    if (!dbg_mutex) {
        HMODULE krnl_lib = GetModuleHandle("Kernel32");
        PFInitializeCriticalSectionAndSpinCount InitializeCriticalSectionAndSpinCount = NULL;

        if (krnl_lib)
            InitializeCriticalSectionAndSpinCount =
                (PFInitializeCriticalSectionAndSpinCount) GetProcAddress(krnl_lib,
                        "InitializeCriticalSectionAndSpinCount");

        dbg_mutex = static_cast<CRITICAL_SECTION*>(xcalloc(1, sizeof(CRITICAL_SECTION)));

        if (InitializeCriticalSectionAndSpinCount) {
            /* let multiprocessor systems EnterCriticalSection() fast */

            if (!InitializeCriticalSectionAndSpinCount(dbg_mutex, 4000)) {
                if (const auto logFile = TheLog.file()) {
                    fprintf(logFile, "FATAL: LogMessage: can't initialize critical section\n");
                    fflush(logFile);
                }

                fprintf(stderr, "FATAL: LogMessage: can't initialize critical section\n");
                abort();
            } else
                InitializeCriticalSection(dbg_mutex);
        }
    }

    EnterCriticalSection(dbg_mutex);
#endif

    char prefix[BUFSIZ];
    prefix[0] = '\0';
    snprintf(prefix, sizeof(prefix), "role=%s %s%s| ",
             myLeadingRole(),
             debugLogTime(),
             debugLogKid());

    const auto level = Debug::Level();
    auto &module = Module();

    module.cacheLogChannel.maybeLog(prefix, message);
    module.errLogChannel.maybeLog(level, prefix, message);

#if HAVE_SYSLOG
    module.sysLogChannel.maybeLog(forceAlert, level, message);
#endif

    if (ShouldBeSaved(level))
        module.saveEarlyMessage(Debug::Section(), level, forceAlert, prefix, message);

#if _SQUID_WINDOWS_
    LeaveCriticalSection(dbg_mutex);
#endif
}

#if HAVE_SYSLOG

static int
SyslogLevel(const int forceAlert, const int level)
{
    return forceAlert ? LOG_ALERT : (level == 0 ? LOG_WARNING : LOG_NOTICE);
}

void
SysLogChannel::maybeLog(const bool forceAlert, const int level, const std::string &message)
{
    if (!flushed)
        return;

    /* level 0,1 go to syslog */

    if (!forceAlert) {
        if (level > DBG_IMPORTANT)
            return;

        if (!Debug::log_syslog)
            return;
    }

    syslog(SyslogLevel(forceAlert, level), "%s", message.c_str());
    ++logged;
}
#endif /* HAVE_SYSLOG */

static void
debugArg(const char *arg)
{
    int s = 0;
    int l = 0;

    if (!strncasecmp(arg, "rotate=", 7)) {
        arg += 7;
        Debug::rotateNumber = atoi(arg);
        return;
    } else if (!strncasecmp(arg, "ALL", 3)) {
        s = -1;
        arg += 4;
    } else {
        s = atoi(arg);
        while (*arg && *arg++ != ',');
    }

    l = atoi(arg);
    assert(s >= -1);

    if (s >= MAX_DEBUG_SECTIONS)
        s = MAX_DEBUG_SECTIONS-1;

    if (l < 0)
        l = 0;

    if (l > 10)
        l = 10;

    if (s >= 0) {
        Debug::Levels[s] = l;
        return;
    }

    ResetSections(l);
}

static void
debugOpenLog(const char *logfile)
{
    assert(logfile);

    // Bug 4423: ignore the stdio: logging module name if present
    const char *logfilename;
    if (strncmp(logfile, "stdio:",6) == 0)
        logfilename = logfile + 6;
    else
        logfilename = logfile;

    if (auto log = fopen(logfilename, "a+")) {
#if _SQUID_WINDOWS_
        setmode(fileno(log), O_TEXT);
#endif
        TheLog.reset(log, logfilename);
        Module().cacheLogChannel.stopEarlyMessageCollection();
    } else {
        const auto xerrno = errno;
        TheLog.fail();
        Module().cacheLogChannel.switchToErrLog();
        // Report the problem after switchToErrLog() to improve our chances of
        // also reporting early debugs() messages (that should be logged first).
        debugs(0, DBG_CRITICAL, "ERROR: Cannot open cache_log (" << logfilename << ") for writing;" <<
               Debug::Extra << "now using stderr instead;" <<
               Debug::Extra << "fopen(3) error: " << xstrerr(xerrno));
    }
}

#if HAVE_SYSLOG
#ifdef LOG_LOCAL4

static struct syslog_facility_name {
    const char *name;
    int facility;
}

syslog_facility_names[] = {

#ifdef LOG_AUTH
    {
        "auth", LOG_AUTH
    },
#endif
#ifdef LOG_AUTHPRIV
    {
        "authpriv", LOG_AUTHPRIV
    },
#endif
#ifdef LOG_CRON
    {
        "cron", LOG_CRON
    },
#endif
#ifdef LOG_DAEMON
    {
        "daemon", LOG_DAEMON
    },
#endif
#ifdef LOG_FTP
    {
        "ftp", LOG_FTP
    },
#endif
#ifdef LOG_KERN
    {
        "kern", LOG_KERN
    },
#endif
#ifdef LOG_LPR
    {
        "lpr", LOG_LPR
    },
#endif
#ifdef LOG_MAIL
    {
        "mail", LOG_MAIL
    },
#endif
#ifdef LOG_NEWS
    {
        "news", LOG_NEWS
    },
#endif
#ifdef LOG_SYSLOG
    {
        "syslog", LOG_SYSLOG
    },
#endif
#ifdef LOG_USER
    {
        "user", LOG_USER
    },
#endif
#ifdef LOG_UUCP
    {
        "uucp", LOG_UUCP
    },
#endif
#ifdef LOG_LOCAL0
    {
        "local0", LOG_LOCAL0
    },
#endif
#ifdef LOG_LOCAL1
    {
        "local1", LOG_LOCAL1
    },
#endif
#ifdef LOG_LOCAL2
    {
        "local2", LOG_LOCAL2
    },
#endif
#ifdef LOG_LOCAL3
    {
        "local3", LOG_LOCAL3
    },
#endif
#ifdef LOG_LOCAL4
    {
        "local4", LOG_LOCAL4
    },
#endif
#ifdef LOG_LOCAL5
    {
        "local5", LOG_LOCAL5
    },
#endif
#ifdef LOG_LOCAL6
    {
        "local6", LOG_LOCAL6
    },
#endif
#ifdef LOG_LOCAL7
    {
        "local7", LOG_LOCAL7
    },
#endif
    {
        NULL, 0
    }
};

#endif

static void
_db_set_syslog(const char *facility)
{
    Debug::log_syslog = true;

#ifdef LOG_LOCAL4
#ifdef LOG_DAEMON

    syslog_facility = LOG_DAEMON;
#else

    syslog_facility = LOG_LOCAL4;
#endif /* LOG_DAEMON */

    if (facility) {

        struct syslog_facility_name *n;

        for (n = syslog_facility_names; n->name; ++n) {
            if (strcmp(n->name, facility) == 0) {
                syslog_facility = n->facility;
                return;
            }
        }

        fprintf(stderr, "unknown syslog facility '%s'\n", facility);
        exit(EXIT_FAILURE);
    }

#else
    if (facility)
        fprintf(stderr, "syslog facility type not supported on your system\n");

#endif /* LOG_LOCAL4 */
}

#endif

void
Debug::ConfigureSysLogging(const char *facility)
{
#if HAVE_SYSLOG
    _db_set_syslog(facility);
#else
    (void)facility;
    // TODO: Throw.
    fatalf("Logging to syslog not available on this platform");
#endif
}

// TODO: Undo renaming. Go back to parseOptions() because this method semantics
// has not changed and there are many (needlessly) affected callers.
void
Debug::ConfigureOptions(char const *options)
{
    char *p = NULL;
    char *s = NULL;

    if (override_X) {
        debugs(0, 9, "command-line -X overrides: " << options);
        return;
    }

    ResetSections();

    if (options) {
        p = xstrdup(options);

        for (s = strtok(p, w_space); s; s = strtok(NULL, w_space))
            debugArg(s);

        xfree(p);
    }
}

void
Debug::UseCacheLog()
{
    Debug::ConfigureOptions(debugOptions);
    debugOpenLog(cache_log);
}

void
Debug::BanCacheLogging()
{
    Debug::ConfigureOptions(debugOptions);
    assert(!TheLog.file());
    Module().cacheLogChannel.switchToErrLog();
}

void
Debug::SettleSysLogging()
{
#if HAVE_SYSLOG && defined(LOG_LOCAL4)

    if (Debug::log_syslog)
        openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, syslog_facility);

#endif /* HAVE_SYSLOG */
    Module().sysLogChannel.stopEarlyMessageCollection();
}

void
_db_rotate_log(void)
{
    if (!TheLog.name)
        return;

#ifdef S_ISREG
    struct stat sb;
    if (stat(TheLog.name, &sb) == 0)
        if (S_ISREG(sb.st_mode) == 0)
            return;
#endif

    char from[MAXPATHLEN];
    from[0] = '\0';

    char to[MAXPATHLEN];
    to[0] = '\0';

    /*
     * NOTE: we cannot use xrename here without having it in a
     * separate file -- tools.c has too many dependencies to be
     * used everywhere debug.c is used.
     */
    /* Rotate numbers 0 through N up one */
    for (int i = Debug::rotateNumber; i > 1;) {
        --i;
        snprintf(from, MAXPATHLEN, "%s.%d", TheLog.name, i - 1);
        snprintf(to, MAXPATHLEN, "%s.%d", TheLog.name, i);
#if _SQUID_WINDOWS_
        remove
        (to);
#endif
        errno = 0;
        if (rename(from, to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "log rotation failed: " << xstrerr(saved_errno));
        }
    }

    /* Rotate the current log to .0 */
    if (Debug::rotateNumber > 0) {
        // form file names before we may clear TheLog below
        snprintf(from, MAXPATHLEN, "%s", TheLog.name);
        snprintf(to, MAXPATHLEN, "%s.%d", TheLog.name, 0);

#if _SQUID_WINDOWS_
        errno = 0;
        if (remove(to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "removal of log file " << to << " failed: " << xstrerr(saved_errno));
        }
        TheLog.clear(); // Windows cannot rename() open files
#endif
        errno = 0;
        if (rename(from, to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "renaming file " << from << " to "
                   << to << "failed: " << xstrerr(saved_errno));
        }
    }

    // Close (if we have not already) and reopen the log because
    // it may have been renamed "manually" before HUP'ing us.
    debugOpenLog(Debug::cache_log);
}

static const char *
debugLogTime(void)
{

    time_t t = getCurrentTime();

    struct tm *tm;
    static char buf[128]; // arbitrary size, big enough for the below timestamp strings.
    static time_t last_t = 0;

    if (Debug::Level() > 1) {
        // 4 bytes smaller than buf to ensure .NNN catenation by snprintf()
        // is safe and works even if strftime() fills its buffer.
        char buf2[sizeof(buf)-4];
        tm = localtime(&t);
        strftime(buf2, sizeof(buf2), "%Y/%m/%d %H:%M:%S", tm);
        buf2[sizeof(buf2)-1] = '\0';
        const int sz = snprintf(buf, sizeof(buf), "%s.%03d", buf2, static_cast<int>(current_time.tv_usec / 1000));
        assert(0 < sz && sz < static_cast<int>(sizeof(buf)));
        last_t = t;
    } else if (t != last_t) {
        tm = localtime(&t);
        const int sz = strftime(buf, sizeof(buf), "%Y/%m/%d %H:%M:%S", tm);
        assert(0 < sz && sz <= static_cast<int>(sizeof(buf)));
        last_t = t;
    }

    buf[sizeof(buf)-1] = '\0';
    return buf;
}

static const char *
debugLogKid(void)
{
    if (KidIdentifier != 0) {
        static char buf[16];
        if (!*buf) // optimization: fill only once after KidIdentifier is set
            snprintf(buf, sizeof(buf), " kid%d", KidIdentifier);
        return buf;
    }

    return "";
}

void
xassert(const char *msg, const char *file, int line)
{
    debugs(0, DBG_CRITICAL, "assertion failed: " << file << ":" << line << ": \"" << msg << "\"");

    if (!shutting_down) {
        Debug::Flush();
        abort();
    }
}

Debug::Context *Debug::Current = nullptr;

Debug::Context::Context(const int aSection, const int aLevel):
    section(aSection),
    level(aLevel),
    sectionLevel(Levels[aSection]),
    upper(Current),
    forceAlert(false)
{
    formatStream();
}

/// Optimization: avoids new Context creation for every debugs().
void
Debug::Context::rewind(const int aSection, const int aLevel)
{
    section = aSection;
    level = aLevel;
    sectionLevel = Levels[aSection];
    assert(upper == Current);

    buf.str(std::string());
    buf.clear();
    // debugs() users are supposed to preserve format, but
    // some do not, so we have to waste cycles resetting it for all.
    formatStream();
}

/// configures default formatting for the debugging stream
void
Debug::Context::formatStream()
{
    const static std::ostringstream cleanStream;
    buf.flags(cleanStream.flags() | std::ios::fixed);
    buf.width(cleanStream.width());
    buf.precision(2);
    buf.fill(' ');
    // If this is not enough, use copyfmt(cleanStream) which is ~10% slower.
}

std::ostringstream &
Debug::Start(const int section, const int level)
{
    Context *future = nullptr;

    // prepare future context
    if (Current) {
        // all reentrant debugs() calls get here; create a dedicated context
        future = new Context(section, level);
    } else {
        // Optimization: Nearly all debugs() calls get here; avoid allocations
        static Context *topContext = new Context(1, 1);
        topContext->rewind(section, level);
        future = topContext;
    }

    Current = future;

    return future->buf;
}

void
Debug::Finish()
{
    // TODO: #include "base/CodeContext.h" instead if doing so works well.
    extern std::ostream &CurrentCodeContextDetail(std::ostream &os);
    if (Current->level <= DBG_IMPORTANT)
        Current->buf << CurrentCodeContextDetail;

    LogMessage(Current->forceAlert, Current->buf.str());
    Current->forceAlert = false;

    Context *past = Current;
    Current = past->upper;
    if (Current)
        delete past;
    // else it was a static topContext from Debug::Start()
}

void
Debug::ForceAlert()
{
    //  the ForceAlert(ostream) manipulator should only be used inside debugs()
    if (Current)
        Current->forceAlert = true;
}

std::ostream&
ForceAlert(std::ostream& s)
{
    Debug::ForceAlert();
    return s;
}

/* DebugMessage */

DebugMessage::DebugMessage(const int aSection, const int aLevel, const bool aForceAlert, const char *aPrefix, const std::string &aSuffix):
    section(aSection),
    level(aLevel),
    forceAlert(aForceAlert),
    prefix(aPrefix),
    suffix(aSuffix)
{
}

/* DebugMessages */

void
DebugMessages::insert(const int section, const int level, const bool forceAlert, const char *prefix, const std::string &suffix)
{
    // TODO: Split to move part of the functionality to DebugModule.

    // There should not be a lot of messages since we are only accumulating
    // level-0/1 messages, but we limit accumulation just in case.
    const size_t limit = 1000;
    if (messages.size() >= limit) {
        const auto &errLogChannel = Module().errLogChannel;
        if (errLogChannel.flushed && errLogChannel.logged) {
            // we must just forget all messages to avoid duplicates on stderr
            // XXX: but this does not forget any messages
            dropped++;
            return;
        }
        dropAllToStderr();
    }
    messages.emplace_back(section, level, forceAlert, prefix, suffix);
}

void
DebugMessages::dropAllToStderr()
{
    // TODO: Can we reuse errLogChannel.maybeLog() here?
    for (const auto &message: messages)
        fprintf(stderr, "%s%s\n", message.prefix.c_str(), message.suffix.c_str());
    dropped += messages.size();
    messages.clear();
}

void
DebugMessages::report() const
{
    if (dropped) {
        const auto saved = messages.size();
        debugs(0, DBG_IMPORTANT, "ERROR: Too many early important messages: " << (saved + dropped) <<
               "; saved " << saved << " but dropped " << dropped);
    }
}

/* Raw */

/// print data bytes using hex notation
void
Raw::printHex(std::ostream &os) const
{
    const auto savedFill = os.fill('0');
    const auto savedFlags = os.flags(); // std::ios_base::fmtflags
    os << std::hex;
    std::for_each(data_, data_ + size_,
    [&os](const char &c) { os << std::setw(2) << static_cast<uint8_t>(c); });
    os.flags(savedFlags);
    os.fill(savedFill);
}

std::ostream &
Raw::print(std::ostream &os) const
{
    if (label_)
        os << ' ' << label_ << '[' << size_ << ']';

    if (!size_)
        return os;

    // finalize debugging level if no level was set explicitly via minLevel()
    const int finalLevel = (level >= 0) ? level :
                           (size_ > 40 ? DBG_DATA : Debug::SectionLevel());
    if (finalLevel <= Debug::SectionLevel()) {
        if (label_)
            os << '=';
        else if (useGap_)
            os << ' ';
        if (data_) {
            if (useHex_)
                printHex(os);
            else
                os.write(data_, size_);
        } else {
            os << "[null]";
        }
    }

    return os;
}

