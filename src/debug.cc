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
#include <deque>

/* for shutting_down flag in xassert() */
#include "globals.h"

char *Debug::debugOptions = NULL;
int Debug::override_X = 0;
bool Debug::log_syslog = false;
int Debug::Levels[MAX_DEBUG_SECTIONS];
char *Debug::cache_log = NULL;
int Debug::rotateNumber = -1;

/// a counter related to the number of debugs() calls
using DebugRecordCount = uint64_t;

class DebugModule;

/// Debugging module singleton.
static DebugModule *Module_ = nullptr;

/// a cached calculateMyLeadingRole() result
extern const char *XXX_Role;
const char *XXX_Role = nullptr;

/// debugs() messages with this (or lower) level will be written to stderr
/// (and possibly other channels). Negative values disable stderr logging.
/// This restriction is ignored if Squid tries but fails to open cache.log.
static int MaxErrChannelLevel = -1;

/// MaxErrChannelLevel default; ignored after FinalizeErrChannelLevel()
static int MaxErrChannelLevelDefault = -1;

static const char *debugLogTime(time_t t);
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

static const char *myLeadingRole_XXX();

/// early debugs() with higher level are not buffered and, hence, may be lost
static constexpr int EarlyMessagesMaxLevel = DBG_IMPORTANT;

/// used for the side effect: fills Debug::Levels with the given level
static void
ResetSections(const int level)
{
    for (auto i = 0; i < MAX_DEBUG_SECTIONS; ++i)
        Debug::Levels[i] = level;
}

/// a named FILE* that supports three states: closed/unopened, open, failed.
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

    /// react to a failure to open the cache_log file
    void noteFailure();

    bool failed() { return failed_; }

    /// cache_log stream or nil
    FILE *file() { return file_; }

    char *name = nullptr;

private:
    friend void ResyncDebugLog(FILE *newFile);

    FILE *file_ = nullptr; ///< opened "real" file or nil; never stderr

    bool failed_ = false; ///< whether noteFailure() was called
};

/// debugs() meta-information
class DebugMessageHeader
{
public:
    DebugMessageHeader(const DebugRecordCount aRecordNumber, const bool doForceAlert):
        recordNumber(aRecordNumber),
        timestamp(getCurrentTime()),
        section(Debug::Section()),
        level(Debug::Level()),
        forceAlert(doForceAlert),
        scheduledToBeDropped(false),
        role_XXX(myLeadingRole_XXX())
    {
    }

    DebugRecordCount recordNumber; ///< LogMessage() calls before this message
    time_t timestamp; ///< approximate debugs() call time
    int section; ///< debugs() section
    int level; ///< debugs() level
    bool forceAlert; ///< debugs() forceAlert flag

    /// whether the message will be removed from the early saved messages buffer
    /// after the current logging attempt
    bool scheduledToBeDropped;

    const char *role_XXX; ///< debugs() caller process role
};

/// a fully processed debugs(), ready to be logged
class DebugMessage
{
public:
    using Header = DebugMessageHeader;
    DebugMessage(const Header &aHeader, const std::string &aBody);

    Header header; ///< debugs() meta-information; reflected in log line prefix
    std::string body; ///< the log line after the prefix (without the newline)
};

/// debugs() messages captured in LogMessage() call order
using DebugMessages = std::deque<DebugMessage>;

/// a receiver of debugs() messages (e.g., stderr or cache.log)
class DebugChannel
{
public:
    using EarlyMessages = std::unique_ptr<DebugMessages>;

    explicit DebugChannel(const char * const aName): name(aName), earlyMessages(new DebugMessages()) {}
    virtual ~DebugChannel() {}

    // no copying or moving or any kind (for simplicity sake and to prevent accidental copies)
    DebugChannel(DebugChannel &&) = delete;

    /// end early message buffering, logging any saved messages
    void stopEarlyMessageCollection();

    /// end early message buffering, without logging any saved messages
    /// \returns any saved messages (or nil)
    EarlyMessages releaseEarlyMessages() { return EarlyMessages(earlyMessages.release()); }

    /// Log the message to the channel if the channel accepts (such) messages.
    /// This logging may be delayed until the channel configuration is settled.
    virtual void maybeLog(const DebugMessageHeader &, const std::string &body) = 0;

    /// maybeLog() the given (saved but not yet written "early") messages
    void log(const DebugMessages &);

protected:
    /// stores the given early message (if possible) or forgets it (otherwise)
    /// \returns whether the message was stored
    bool saveMessage(const DebugMessageHeader &header, const std::string &body);

    /// process previously saved messages purged due to capacity limits
    virtual void handleOverflow(DebugMessages &) {}

    /// Formats a validated debugs() record and writes it to the given FILE.
    void logToStream(FILE &, const DebugMessageHeader &, const std::string &body);

    /// reacts to a written a debugs() message
    void noteLogged(const DebugMessageHeader &header);

protected:
    const char * const name = nullptr; ///< unique channel label for debugging

    DebugRecordCount logged = 0; ///< the number of messages logged so far

    /// DebugMessageHeader::recordNumber of the last message we logged
    DebugRecordCount lastLoggedRecordNumber = 0;

    /// debugs() messages waiting for the channel configuration to settle (and
    /// the channel to open) so that their eligibility for logging can be
    /// determined (and the messages can be actually logged somewhere)
    EarlyMessages earlyMessages;
};

/// DebugChannel managing messages destined for the configured cache_log file
class CacheLogChannel: public DebugChannel
{
public:
    CacheLogChannel(): DebugChannel("cache_log") {}

    /* DebugChannel API */
    virtual void maybeLog(const DebugMessageHeader &, const std::string &body) final;
    virtual void handleOverflow(DebugMessages &) final;
};

/// DebugChannel managing messages destined for "standard error stream" (stderr)
class ErrChannel: public DebugChannel
{
public:
    ErrChannel(): DebugChannel("stderr") {}

    /// whether maybeLog() ought to log a corresponding debugs() message
    /// (assuming some higher-level code applied cache.log section/level filter)
    bool shouldLog(const int level, const bool scheduledToBeDropped) const;

    /* DebugChannel API */
    virtual void maybeLog(const DebugMessageHeader &, const std::string &body) final;

    /// Start to take care of past/saved and future cacheLogChannel messages.
    void takeOver(CacheLogChannel &);

    /// Stop providing a cache_log replacement (if we were providing it).
    void stopCoveringCacheLog();

private:
    /// whether we are the last resort for logging debugs() messages
    bool coveringForCacheLog = false;
};

/// syslog DebugChannel
class SyslogChannel: public DebugChannel
{
public:
    SyslogChannel(): DebugChannel("syslog") {}

    /* DebugChannel API */
    virtual void maybeLog(const DebugMessageHeader &, const std::string &body) final;
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

    /// \copydoc Debug::SwanSong()
    void flush();

    /// Log the given debugs() message to appropriate channel(s) (eventually).
    /// Assumes the message has passed the global section/level filter.
    void log(const DebugMessageHeader &header, const std::string &body);

    /// Start using an open cache_log file as the primary debugs() destination.
    /// Stop using stderr as a cache_log replacement (if we were doing that).
    void useCacheLog();

    /// Start using stderr as the primary debugs() destination.
    /// Stop waiting for an open cache_log file (if we were doing that).
    void banCacheLog();

public:
    CacheLogChannel cacheLogChannel;
    ErrChannel stderrChannel;
    SyslogChannel syslogChannel;
};

/// configured cache.log file or stderr
/// safe during static initialization, even if it has not been constructed yet
static DebugFile TheLog;

/* DebugModule */

// Depending on DBG_CRITICAL activity and command line options, this code may
// run as early as static initialization during program startup or as late as
// the first debugs(DBG_CRITICAL) call from the main loop.
DebugModule::DebugModule()
{
    // explicit initialization before any use by debugs() calls; see bug #2656
    tzset();

    (void)std::atexit(&Debug::SwanSong);

    if (!Debug::override_X)
        ResetSections();
}

void
DebugModule::log(const DebugMessageHeader &header, const std::string &body)
{
    cacheLogChannel.maybeLog(header, body);
    stderrChannel.maybeLog(header, body);
    syslogChannel.maybeLog(header, body);
}

void
DebugModule::flush()
{
    stderrChannel.stopEarlyMessageCollection();
    syslogChannel.stopEarlyMessageCollection();
    cacheLogChannel.stopEarlyMessageCollection();
}

void
DebugModule::useCacheLog()
{
    assert(TheLog.file());
    stderrChannel.stopCoveringCacheLog(); // in case it was covering
    cacheLogChannel.stopEarlyMessageCollection();
}

void
DebugModule::banCacheLog()
{
    assert(!TheLog.file());
    stderrChannel.takeOver(cacheLogChannel);
}

/// safe access to the debugging module
static
DebugModule &
Module() {
    if (!Module_) {
        Module_ = new DebugModule();
#if !defined(HAVE_SYSLOG)
        // Optimization: Do not wait for others to tell us what we already know.
        Debug::SettleSysLogChannel();
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
DebugChannel::stopEarlyMessageCollection()
{
    if (const auto toLog = releaseEarlyMessages())
        log(*toLog);
}

// XXX: call banCacheLog() if necessary to force logging of buffered
// messages. Otherwise, they will not be shown if we have not opened cache_log
// before abort()ing.
void
Debug::SwanSong()
{
    Module().flush();
}

void
DebugChannel::log(const DebugMessages &messages)
{
    const auto loggedEarlier = logged;
    for (const auto &message: messages) {
        if (Debug::Enabled(message.header.section, message.header.level) &&
                lastLoggedRecordNumber < message.header.recordNumber)
            maybeLog(message.header, message.body);
    }
    const auto loggedNow = logged - loggedEarlier;
    debugs(0, 5, "wrote " << loggedNow << " out of " <<
           messages.size() << " early messages to " << name);
}

bool
DebugChannel::saveMessage(const DebugMessageHeader &header, const std::string &body)
{
    if (!earlyMessages)
        return false;

    if (header.level > EarlyMessagesMaxLevel)
        return false;

    // There should not be a lot of messages because EarlyMessagesMaxLevel is
    // small, but we limit their accumulation just in case.
    const DebugMessages::size_type limit = 1000;
    DebugMessages::size_type purged = 0;
    if (earlyMessages->size() >= limit) {
        DebugMessages doomedMessages;
        earlyMessages->swap(doomedMessages);
        handleOverflow(doomedMessages);
        purged = doomedMessages.size();
    }

    earlyMessages->emplace_back(header, body);

    // Log/save the error message below _after_ saving the early message above,
    // preserving the original event and LogMessage() order, like maybeLog().
    if (purged) {
        debugs(0, DBG_CRITICAL, "ERROR: Too many early important messages. " <<
               "Purged " << purged << " from " << name);
    }

    return true;
}

void
DebugChannel::logToStream(FILE &destination, const DebugMessageHeader &header, const std::string &body)
{
    fprintf(&destination, "role=%s # %s%s| %s\n",
            header.role_XXX,
            debugLogTime(header.timestamp),
            debugLogKid(),
            body.c_str());
    noteLogged(header);
}

void
DebugChannel::noteLogged(const DebugMessageHeader &header)
{
    ++logged;
    lastLoggedRecordNumber = header.recordNumber;
}

/* CacheLogChannel */

void
CacheLogChannel::maybeLog(const DebugMessageHeader &header, const std::string &body)
{
    assert(header.recordNumber > lastLoggedRecordNumber);

    if (earlyMessages)
        return (void)saveMessage(header, body);

    if (!TheLog.file())
        return;

    logToStream(*TheLog.file(), header, body);
    fflush(TheLog.file());
}

void
CacheLogChannel::handleOverflow(DebugMessages &doomedMessages)
{
    for (auto &message: doomedMessages)
        message.header.scheduledToBeDropped = true;
    Module().stderrChannel.log(doomedMessages);
}

/* ErrChannel */

bool
ErrChannel::shouldLog(const int level, const bool scheduledToBeDropped) const
{
    if (!stderr)
        return false; // nowhere to log

    // whether the given level is allowed by circumstances (coveringForCacheLog,
    // early message storage overflow, etc.) or configuration (-d, -k, etc.)
    return coveringForCacheLog || scheduledToBeDropped || level <= MaxErrChannelLevel;
}

void
ErrChannel::maybeLog(const DebugMessageHeader &header, const std::string &body)
{
    assert(header.recordNumber > lastLoggedRecordNumber);

    if (saveMessage(header, body))
        return;

    if (!shouldLog(header.level, header.scheduledToBeDropped))
        return;

    // We must log this eligible unsaved message, but we must log previously
    // saved early messages before logToStream() below to avoid reordering.
    stopEarlyMessageCollection();

    logToStream(*stderr, header, body);
}

void
ErrChannel::takeOver(CacheLogChannel &cacheLogChannel)
{
    if (coveringForCacheLog)
        return;

    coveringForCacheLog = true;

    // Stop collecting before dumping cacheLogChannel messages so that we do not
    // end up saving messages already saved by cacheLogChannel.
    stopEarlyMessageCollection();
    if (const auto theirs = cacheLogChannel.releaseEarlyMessages())
        log(*theirs);
}

void
ErrChannel::stopCoveringCacheLog()
{
    if (!coveringForCacheLog)
        return;

    coveringForCacheLog = false;
    debugs(0, DBG_IMPORTANT, "Resuming logging to cache_log");
}

void
Debug::EnsureDefaultErrChannelLevel(const int maxDefault)
{
    if (MaxErrChannelLevelDefault < maxDefault)
        MaxErrChannelLevelDefault = maxDefault; // may set or increase
    // else: somebody has already requested a more permissive maximum
}

void
Debug::ResetErrChannelLevel(const int maxLevel)
{
    MaxErrChannelLevel = maxLevel; // may set, increase, or decrease
}

void
Debug::SettleErrChannel()
{
    if (MaxErrChannelLevel < 0)
        MaxErrChannelLevel = MaxErrChannelLevelDefault; // may remain disabled/negative

    Module().stderrChannel.stopEarlyMessageCollection();
}

bool
Debug::ErrChannelEnabled()
{
    return Module().stderrChannel.shouldLog(DBG_CRITICAL, false);
}

/* DebugMessage */

DebugMessage::DebugMessage(const Header &aHeader, const std::string &aBody):
    header(aHeader),
    body(aBody)
{
}

/* DebugFile */

void DebugFile::noteFailure()
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
myLeadingRole_XXX()
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
                    fprintf(logFile, "FATAL: %s: can't initialize critical section\n", __FUNCTION__);
                    fflush(logFile);
                }

                fprintf(stderr, "FATAL: %s: can't initialize critical section\n", __FUNCTION__);
                abort();
            } else
                InitializeCriticalSection(dbg_mutex);
        }
    }

    EnterCriticalSection(dbg_mutex);
#endif

    static DebugRecordCount LogMessageCalls = 0;
    const DebugMessageHeader header(++LogMessageCalls, forceAlert);
    Module().log(header, message);

#if _SQUID_WINDOWS_
    LeaveCriticalSection(dbg_mutex);
#endif
}

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
        Module().useCacheLog();
    } else {
        const auto xerrno = errno;
        TheLog.noteFailure();
        Module().banCacheLog();

        // Report the problem after the switch above to improve our chances of
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

/* SyslogChannel */

static int
SyslogPriority(const DebugMessageHeader &header)
{
    return header.forceAlert ? LOG_ALERT :
           (header.level == 0 ? LOG_WARNING : LOG_NOTICE);
}

void
SyslogChannel::maybeLog(const DebugMessageHeader &header, const std::string &body)
{
    assert(header.recordNumber > lastLoggedRecordNumber);

    if (earlyMessages)
        return (void)saveMessage(header, body);

    /* level 0,1 go to syslog */

    if (!header.forceAlert) {
        if (header.level > DBG_IMPORTANT)
            return;

        if (!Debug::log_syslog)
            return;
    }

    syslog(SyslogPriority(header), "%s", body.c_str());
    noteLogged(header);
}

#else

void
SyslogChannel::maybeLog(const DebugMessageHeader &, const std::string &)
{
    // nothing to do when we do not support logging to syslog
}
#endif /* HAVE_SYSLOG */

void
Debug::ConfigureSysLog(const char *facility)
{
#if HAVE_SYSLOG
    _db_set_syslog(facility);
#else
    (void)facility;
    // TODO: Throw.
    fatalf("Logging to syslog not available on this platform");
#endif
}

void
Debug::parseOptions(char const *options)
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
    Debug::parseOptions(debugOptions);
    debugOpenLog(cache_log);
}

void
Debug::BanCacheLogging()
{
    Debug::parseOptions(debugOptions);
    Module().banCacheLog();
}

void
Debug::SettleSysLogChannel()
{
#if HAVE_SYSLOG && defined(LOG_LOCAL4)

    if (Debug::log_syslog)
        openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, syslog_facility);

#endif /* HAVE_SYSLOG */

    Module().syslogChannel.stopEarlyMessageCollection();
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
debugLogTime(const time_t t)
{
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

/// The number of xassert() calls in the call stack. Treat as private to
/// xassert(): It is moved out only to simplify the asserting code path.
static auto Asserting_ = false;

void
xassert(const char *msg, const char *file, int line)
{
    // if the non-trivial code below has itself asserted, then simplify instead
    // of running out of stack and complicating triage
    if (Asserting_)
        abort();

    Asserting_ = true;

    debugs(0, DBG_CRITICAL, "assertion failed: " << file << ":" << line << ": \"" << msg << "\"");

    if (!shutting_down) {
        Debug::SwanSong();
        abort();
    }

    Asserting_ = false;
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

