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
int Debug::MaxErrLogLevel = -1;
int Debug::MaxErrLogLevelDefault = -1;

static const char *debugLogTime(void);
static const char *debugLogKid(void);
#if HAVE_SYSLOG
#ifdef LOG_LOCAL4
static int syslog_facility = 0;
#endif
static void _db_print_syslog(const bool forceAlert, const char *format, va_list args);
#endif
static void _db_print_stderr(const char *format, va_list args);
static void _db_print_file(const char *format, va_list args);
static void _db_print_early_message(const bool forceAlert, const char *format, va_list args);

#if _SQUID_WINDOWS_
extern LPCRITICAL_SECTION dbg_mutex;
typedef BOOL (WINAPI * PFInitializeCriticalSectionAndSpinCount) (LPCRITICAL_SECTION, DWORD);
#endif

static void ResetSections(const int level = DBG_IMPORTANT);

/// early debugs() with higher level are not buffered and, hence, may be lost
static constexpr int EarlyMessagesMaxLevel = DBG_IMPORTANT;

static void Initialize();
static bool Initialized = (Initialize(), true);

/// used for the side effect: performs earliest module initialization possible
static void
Initialize()
{
    // explicit initialization, hopefully before any debugs() calls; see bug #2656
    tzset();

    (void)std::atexit(&Debug::Flush);

    ResetSections();

    assert(sizeof(Initialized)); // avoids warnings about an unused static
}

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

/// receivers of debugs() messages
enum DebugChannel {
    ErrChannel = 0x1, // stderr
    CacheChannel = 0x2, // cache.log
    SysChannel = 0x4 // syslog()
};

/// a stored debugs() message
class DebugMessage
{
public:
    DebugMessage(const int section, const int level, const bool forceAlert, const char *format, va_list args);

    /// whether the channel expects this message
    bool allowed(const DebugChannel) const;

    int section; ///< the debug section
    int level; ///< the debug level
    bool forceAlert; ///< the debugs() forceAlert flag
    char image[BUFSIZ]; ///< formatted message (including timestamp and context)
};

// TODO: Rename to EarlyDebugMessages or some such because the class has code
// specific to handling early messages.
/// preserves (a limited amount of) debugs() messages for delayed logging
class DebugMessages
{
public:
    DebugMessages() = default;
    ~DebugMessages();
    // no copying or moving or any kind (for simplicity sake and to prevent accidental copies)
    DebugMessages(DebugMessages &&) = delete;

    /// stores the given message (if possible) or forgets it (otherwise)
    void insert(const int section, const int level, const bool forceAlert, const char *format, va_list args);
    /// whether the stored messages were written to a given channel
    bool flushed(const DebugChannel ch) const { return ch & flushedChannels; }
    /// whether the stored messages were written to all channels
    bool flushedAll() const { return flushedChannels == (ErrChannel|CacheChannel|SysChannel); };
    /// logs all previously stored messages
    void flush(const DebugChannel);

private:
    void dropAllToStderr();

    typedef std::vector<DebugMessage> Storage;
    Storage messages;

    /// the total number of messages we could not store (due to capacity limits)
    uint64_t dropped = 0;
    uint64_t flushedChannels = 0;; ///< flushed channels bitmask
};

/// Preserves important debugs() messages until the log file gets opened and
/// then logs those messages. Must be accessed via EarlyMessages() except for
/// assignment.
static DebugMessages *EarlyMessagesOrNil = nullptr;

// Becomes true during C++ constant initialization, before any debugs() calls.
// Exists because EarlyMessages cannot be set during constant initialization.
/// whether "early" messages may need to be accumulated and/or logged
static bool SavingEarlyMessages = true;

/// configured cache.log file or stderr
/// safe during static initialization, even if it has not been constructed yet
static DebugFile TheLog;

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

/// Provides access to early messages in (and only in) SavingEarlyMessages mode.
DebugMessages &
EarlyMessages()
{
    assert(SavingEarlyMessages);
    if (!EarlyMessagesOrNil)
        EarlyMessagesOrNil = new DebugMessages;
    return *EarlyMessagesOrNil;
}

/// Write all saved but not yet written "early" messages into the given channel.
static void
FlushEarlyMessagesTo(const DebugChannel ch)
{
    if (!SavingEarlyMessages)
        return;

    // This may create an early message buffer, and we need that creation to
    // keep track of what has been flushed. TODO: Refactor to avoid creation.
    EarlyMessages().flush(ch);
}

/// End early message buffering for the given channel, flushing saved messages.
/// If no channel still needs buffering, stop saving early messages.
static void
StopEarlyMessageCollectionFor(const DebugChannel ch)
{
    if (!SavingEarlyMessages)
        return;

    // This may create an early message buffer, and we need that creation to
    // keep track of what has been flushed. TODO: Refactor to avoid creation.
    FlushEarlyMessagesTo(ch);

    if (EarlyMessages().flushedAll()) {
        SavingEarlyMessages = false;
        delete EarlyMessagesOrNil;
        EarlyMessagesOrNil = nullptr;
    }
}

void
Debug::Flush()
{
    if (SavingEarlyMessages) {
        // some of channels may not be flushed yet
        FlushEarlyMessagesTo(ErrChannel);
        FlushEarlyMessagesTo(SysChannel);
        FlushEarlyMessagesTo(CacheChannel);
    }
}

/// whether we are still saving early messages into a given channel
static bool
SavingEarlyMessagesToChannel(const DebugChannel &ch)
{
    return SavingEarlyMessages && !EarlyMessages().flushed(ch);
}

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

    if (file_) {
        fd_open(fileno(file_), FD_LOG, Debug::cache_log);
    }

    xfree(name);
    name = newName ? xstrdup(newName) : nullptr;

    // all open files must have a name
    // all cleared files must not have a name
    assert(!file_ == !name);
}

/// a cached calculateMyLeadingRole() result
extern const char *XXX_Role;
const char *XXX_Role = nullptr;

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
_db_print(const bool forceAlert, const char *format,...)
{
    char f[BUFSIZ];
    f[0]='\0';
    va_list args1;
    va_list args2;
    va_list args3;

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
                    fprintf(logFile, "FATAL: _db_print: can't initialize critical section\n");
                    fflush(logFile);
                }

                fprintf(stderr, "FATAL: _db_print: can't initialize critical section\n");
                abort();
            } else
                InitializeCriticalSection(dbg_mutex);
        }
    }

    EnterCriticalSection(dbg_mutex);
#endif

    va_start(args1, format);
    va_start(args2, format);
    va_start(args3, format);

    snprintf(f, BUFSIZ, "role=%s %s%s| %s",
             myLeadingRole(),
             debugLogTime(),
             debugLogKid(),
             format);

    _db_print_file(f, args1);
    _db_print_stderr(f, args2);

#if HAVE_SYSLOG
    _db_print_syslog(forceAlert, format, args3);
#endif

    if (SavingEarlyMessages && Debug::Level() <= EarlyMessagesMaxLevel) {
        va_list args4;
        va_start(args4, format);
        // XXX: _db_print_syslog() uses format `format`, not `f`!
        _db_print_early_message(forceAlert, f, args4);
        va_end(args4);
    }

#if _SQUID_WINDOWS_
    LeaveCriticalSection(dbg_mutex);
#endif

    va_end(args1);
    va_end(args2);
    va_end(args3);
}

static void
_db_print_file(const char *format, va_list args)
{
    if (!TheLog.file())
        return;

    if (SavingEarlyMessagesToChannel(CacheChannel))
        return;

    vfprintf(TheLog.file(), format, args);
    fflush(TheLog.file());
}

static void
_db_print_early_message(const bool forceAlert, const char *format, va_list args)
{
    EarlyMessages().insert(Debug::Section(), Debug::Level(), forceAlert, format, args);
}

bool
Debug::ErrLogEnabled(const int level)
{
    return level <= MaxErrLogLevel || TheLog.failed();
}

static void
_db_print_stderr(const char *format, va_list args)
{
    if (!Debug::ErrLogEnabled(Debug::Level()))
        return;

    if (SavingEarlyMessagesToChannel(ErrChannel))
        return;

    vfprintf(stderr, format, args);
}

#if HAVE_SYSLOG

static int
SyslogLevel(const int forceAlert, const int level)
{
    return forceAlert ? LOG_ALERT : (level == 0 ? LOG_WARNING : LOG_NOTICE);
}

static bool
SysLogAllowed(const int forceAlert, const int level)
{
    return forceAlert || (Debug::log_syslog && (level <= DBG_IMPORTANT));
}

static void
_db_print_syslog(const bool forceAlert, const char *format, va_list args)
{
    // XXX: The old comment below is now misplaced. Remove?
    /* level 0,1 go to syslog */

    if (!SysLogAllowed(forceAlert, Debug::Level()))
        return;

    if (SavingEarlyMessagesToChannel(SysChannel))
        return;

    char tmpbuf[BUFSIZ];
    tmpbuf[0] = '\0';

    vsnprintf(tmpbuf, BUFSIZ, format, args);

    tmpbuf[BUFSIZ - 1] = '\0';

    syslog(SyslogLevel(forceAlert, Debug::Level()), "%s", tmpbuf);
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
    if (logfile == NULL) {
        TheLog.clear();
        return;
    }

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
    } else {
        // XXX: Bypassing debugs() (with its early message buffering) results in
        // out-of-order stderr lines (e.g. squid -NX prints these lines first).
        fprintf(stderr, "WARNING: Cannot write log file: %s\n", logfile);
        perror(logfile);
        fprintf(stderr, "         messages will be sent to 'stderr'.\n");
        fflush(stderr);
        TheLog.fail();
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

    // XXX: This is too early iff TheLog.failed() becomes true later!
    StopEarlyMessageCollectionFor(ErrChannel);
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
    StopEarlyMessageCollectionFor(CacheChannel);
}

void
Debug::BanCacheLogging()
{
    Debug::ConfigureOptions(debugOptions);
    assert(!TheLog.file());
    StopEarlyMessageCollectionFor(CacheChannel);
}

void
Debug::SettleSysLogging()
{
#if HAVE_SYSLOG && defined(LOG_LOCAL4)

    if (Debug::log_syslog)
        openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, syslog_facility);

#endif /* HAVE_SYSLOG */
    StopEarlyMessageCollectionFor(SysChannel);
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

    // TODO: Optimize to remove at least one extra copy.
    _db_print(Current->forceAlert, "%s\n", Current->buf.str().c_str());
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

DebugMessage::DebugMessage(const int aSection, const int aLevel, const bool aForceAlert, const char *format, va_list args):
    section(aSection),
    level(aLevel),
    forceAlert(aForceAlert)
{
    // The two paranoid(?) termination lines below are meant for vsnprintf()
    // implementations that do not terminate on various kinds of errors.
    // TODO: Unify all Squid vsnprintf() calls, probably using std::vsnprintf().
    image[0] = '\0';
    (void)vsnprintf(image, sizeof(image), format, args);
    image[sizeof(image)-1] = '\0';
}

/* DebugMessages */

DebugMessages::~DebugMessages()
{
    if (dropped) {
        const auto saved = messages.size();
        debugs(0, DBG_IMPORTANT, "ERROR: Too many early important messages: " << (saved + dropped) <<
               "; saved " << saved << " but dropped " << dropped);
    }
}

void
DebugMessages::insert(const int section, const int level, const bool forceAlert, const char *format, va_list args)
{
    // There should not be a lot of messages since we are only accumulating
    // level-0/1 messages, but we limit accumulation just in case.
    const size_t limit = 1000;
    if (messages.size() >= limit) {
        if (flushed(ErrChannel)) {
            // XXX: This avoids duplicates but may also lose messages if
            // stderr is not logging them (e.g. no -d).
            dropped++;
            return;
        }
        dropAllToStderr();
    }
    messages.emplace_back(section, level, forceAlert, format, args);
}

bool
DebugMessage::allowed(const DebugChannel ch) const
{
    if (!Debug::Enabled(section, level))
        return false;

    if (ch == ErrChannel) {
        return Debug::ErrLogEnabled(level);
    }
    else if (ch == CacheChannel)
        return true; // we already checked level above
    else {
        assert(ch == SysChannel);
        return SysLogAllowed(forceAlert, level);
    }
}

void
DebugMessages::dropAllToStderr()
{
    for (const auto &message: messages)
        fprintf(stderr, "%s", message.image);
    dropped += messages.size();
    messages.clear();
}

static FILE *
ChannelStream(const DebugChannel ch)
{
    if (ch == ErrChannel)
        return stderr;
    else if (ch == CacheChannel)
        return TheLog.file();
    else {
        assert(ch == SysChannel);
        return nullptr;
    }
}

static const char *
ChannelName(const DebugChannel ch)
{
    if (ch == ErrChannel)
        return "stderr";
    else if (ch == CacheChannel)
        return "cache.log";
    else {
        assert(ch == SysChannel);
        return "syslog";
    }
}

void
DebugMessages::flush(const DebugChannel ch)
{
    // Once a channel is flushed, it starts writing messages immediately (TODO:
    // Check that!); no buffered message can be for that channel after that.
    if (flushed(ch))
        return;

    flushedChannels |= ch;
    const auto log = ChannelStream(ch);
    uint64_t logged = 0;
    for (const auto &message: messages) {
        if (message.allowed(ch)) {
            if (log) {
                assert(ch == ErrChannel || ch == CacheChannel);
                fprintf(log, "%s", message.image);
                logged++;;
            }
#if HAVE_SYSLOG
            else if (ch == SysChannel) {
                syslog(SyslogLevel(message.forceAlert, message.level), "%s", message.image);
                logged++;;
            }
#endif
        }
    }
    if (log)
        fflush(log);

if (stderr) fprintf(stderr, "role=%s XXX: DebugMessages::flush(%s) saved=%d, logged=%d\n", XXX_Role, ChannelName(ch), int(messages.size()), int(logged));

    // Use debugs() level that prevents message buffering. Otherwise, this could
    // overflow the messages buffer, and dropAllToStderr() could dump the lines
    // we just reported above, possibly duplicating the lines on stderr.
    debugs(0, EarlyMessagesMaxLevel+1, "wrote " << logged << " out of " <<
           messages.size() << " early messages to " << ChannelName(ch));
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

