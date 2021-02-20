/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#ifndef SQUID_DEBUG_H
#define SQUID_DEBUG_H

// XXX should be mem/forward.h once it removes dependencies on typedefs.h
#include "mem/AllocatorProxy.h"

#include <iostream>
#undef assert
#include <sstream>
#include <iomanip>
#if defined(assert)
#undef assert
#endif

#if PURIFY
#define assert(EX) ((void)0)
#elif defined(NODEBUG)
#define assert(EX) ((void)0)
#elif STDC_HEADERS
#define assert(EX)  ((EX)?((void)0):xassert( # EX , __FILE__, __LINE__))
#else
#define assert(EX)  ((EX)?((void)0):xassert("EX", __FILE__, __LINE__))
#endif

/* defined debug section limits */
#define MAX_DEBUG_SECTIONS 100

/* defined names for Debug Levels */
#define DBG_CRITICAL    0   /**< critical messages always shown when they occur */
#define DBG_IMPORTANT   1   /**< important messages always shown when their section is being checked */
/* levels 2-8 are still being discussed amongst the developers */
#define DBG_DATA    9   /**< output is a large data dump only necessary for advanced debugging */

#define DBG_PARSE_NOTE(x) (opt_parse_cfg_only?0:(x)) /**< output is always to be displayed on '-k parse' but at level-x normally. */

class Debug
{

public:
    /// meta-information for debugs() or a similar debugging call
    class Context
    {
    public:
        Context(const int aSectionLevel, const int aLevel);

        int level; ///< minimum debugging level required by the debugs() call
        int sectionLevel; ///< maximum debugging level allowed during the call

    private:
        friend class Debug;
        void rewind(const int aSection, const int aLevel);
        void formatStream();
        Context *upper; ///< previous or parent record in nested debugging calls
        std::ostringstream buf; ///< debugs() output sink
    };

    /// whether debugging the given section and the given level produces output
    static bool Enabled(const int section, const int level)
    {
        return level <= Debug::Levels[section];
    }

    static char *debugOptions;
    static char *cache_log;
    static int rotateNumber;
    static int Levels[MAX_DEBUG_SECTIONS];
    static int override_X;
    static int log_stderr;
    static bool log_syslog;
    static bool ForceAlert; ///< Hack: The next debugs() will be a syslog ALERT.

    static void parseOptions(char const *);

    /// minimum level required by the current debugs() call
    static int Level() { return Current ? Current->level : 1; }
    /// maximum level currently allowed
    static int SectionLevel() { return Current ? Current->sectionLevel : 1; }

    /// opens debugging context and returns output buffer
    static std::ostringstream &Start(const int section, const int level);
    /// logs output buffer created in Start() and closes debugging context
    static void Finish();

    /// prefixes each grouped debugs() line after the first one in the group
    static std::ostream& Extra(std::ostream &os) { return os << "\n    "; }

private:
    static Context *Current; ///< deepest active context; nil outside debugs()
};

extern FILE *debug_log;

size_t BuildPrefixInit();
const char * SkipBuildPrefix(const char* path);

/* Debug stream
 *
 * Unit tests can enable full debugging to stderr for one
 * debug section; to enable this, #define ENABLE_DEBUG_SECTION to the
 * section number before any header
 */
#define debugs(SECTION, LEVEL, CONTENT) \
   do { \
        const int _dbg_level = (LEVEL); \
        if (Debug::Enabled((SECTION), _dbg_level)) { \
            std::ostream &_dbo = Debug::Start((SECTION), _dbg_level); \
            if (_dbg_level > DBG_IMPORTANT) { \
                _dbo << (SECTION) << ',' << _dbg_level << "| " \
                     << SkipBuildPrefix(__FILE__)<<"("<<__LINE__<<") "<<__FUNCTION__<<": "; \
            } \
            _dbo << CONTENT; \
            Debug::Finish(); \
        } \
   } while (/*CONSTCOND*/ 0)

/** stream manipulator which does nothing.
 * \deprecated Do not add to new code, and remove when editing old code
 *
 * Its purpose is to inactivate calls made following previous debugs()
 * guidelines such as
 * debugs(1,2, HERE << "some message");
 *
 * His former objective is now absorbed in the debugs call itself
 */
inline std::ostream&
HERE(std::ostream& s)
{
    return s;
}

/*
 * MYNAME is for use at debug levels 0 and 1 where HERE is too messy.
 *
 * debugs(1,1, MYNAME << "WARNING: some message");
 */
#ifdef __PRETTY_FUNCTION__
#define MYNAME __PRETTY_FUNCTION__ << " "
#else
#define MYNAME __FUNCTION__ << " "
#endif

/* some uint8_t do not like streaming control-chars (values 0-31, 127+) */
inline std::ostream& operator <<(std::ostream &os, const uint8_t d)
{
    return (os << (int)d);
}

/* Legacy debug function definitions */
void _db_init(const char *logfile, const char *options);
void _db_print(const char *,...) PRINTF_FORMAT_ARG1;
void _db_set_syslog(const char *facility);
void _db_rotate_log(void);

/// Prints raw and/or non-terminated data safely, efficiently, and beautifully.
/// Allows raw data debugging in debugs() statements with low debugging levels
/// by printing only if higher section debugging levels are configured:
///   debugs(11, DBG_IMPORTANT, "always printed" << Raw(may be printed...));
class Raw
{
public:
    Raw(const char *label, const char *data, const size_t size):
        level(-1), label_(label), data_(data), size_(size), useHex_(false) {}

    /// limit data printing to at least the given debugging level
    Raw &minLevel(const int aLevel) { level = aLevel; return *this; }

    /// print data using two hex digits per byte (decoder: xxd -r -p)
    Raw &hex() { useHex_ = true; return *this; }

    /// If debugging is prohibited by the current debugs() or section level,
    /// prints nothing. Otherwise, dumps data using one of these formats:
    ///   " label[size]=data" if label was set and data size is positive
    ///   " label[0]" if label was set and data size is zero
    ///   " data" if label was not set and data size is positive
    ///   "" (i.e., prints nothing) if label was not set and data size is zero
    std::ostream &print(std::ostream &os) const;

    /// Minimum section debugging level necessary for printing. By default,
    /// small strings are always printed while large strings are only printed
    /// if DBG_DATA debugging level is enabled.
    int level;

private:
    void printHex(std::ostream &os) const;

    const char *label_; ///< optional data name or ID; triggers size printing
    const char *data_; ///< raw data to be printed
    size_t size_; ///< data length
    bool useHex_; ///< whether hex() has been called
};

inline
std::ostream &operator <<(std::ostream &os, const Raw &raw)
{
    return raw.print(os);
}

/// debugs objects pointed by possibly nil pointers: label=object
template <class Pointer>
class RawPointerT {
public:
    RawPointerT(const char *aLabel, const Pointer &aPtr):
        label(aLabel), ptr(aPtr) {}
    const char *label; /// the name or description of the being-debugged object
    const Pointer &ptr; /// a possibly nil pointer to the being-debugged object
};

/// convenience wrapper for creating  RawPointerT<> objects
template <class Pointer>
inline RawPointerT<Pointer>
RawPointer(const char *label, const Pointer &ptr)
{
    return RawPointerT<Pointer>(label, ptr);
}

/// prints RawPointerT<>, dereferencing the raw pointer if possible
template <class Pointer>
inline std::ostream &
operator <<(std::ostream &os, const RawPointerT<Pointer> &pd)
{
    os << pd.label << '=';
    if (pd.ptr)
        return os << *pd.ptr;
    else
        return os << "[nil]";
}

// XXX: Move to src/DebugMessages.h
#ifndef SQUID_DEBUG_MESSAGES_H
#define SQUID_DEBUG_MESSAGES_H

#include <limits>
#include <array>

// XXX: Replace Debug class with namespace and use that namespace here.

/// an identifier for messages supporting configuration via cache_log_message
typedef unsigned int DebugMessageId;

/// manages configurable aspects of a debugs() message
class DebugMessage
{
public:
    /// whether the logging of this message has been customized
    bool configured() const { return id > 0; }

    /// whether the default logging level of this message has been altered
    bool levelled() const { return level >= 0; }

    /// whether the number of logging attempts have been limited
    bool limited() const { return limit < std::numeric_limits<decltype(limit)>::max(); }

    /// \returns appropriate debugging level for the message
    int currentLevel(const int defaultLevel) const {
        if (configured())
            return (count_++ >= limit) ? DBG_DATA : level;
        return defaultLevel;
    }

    /// message identifier or, if the message has not been configured, zero
    DebugMessageId id = 0;

    /* all these configurable members are ignored unless configured() */

    /// debugging level (i.e., the second debugs() parameter) or -1
    int level = -1;

    /// logging attempts beyond this limit are logged at the DBG_DATA level
    uint64_t limit = std::numeric_limits<uint64_t>::max();

private:
    /// the total number of attempts to log this message if it was configured()
    mutable uint64_t count_ = 0;
};

/// The exact number of supported configurable messages. Increase as needed.
constexpr size_t DebugMessageCount = 64;
/// configurable messages indexed by DebugMessageId
typedef std::array<DebugMessage, DebugMessageCount> DebugMessages;
/// all configurable debugging messages
extern DebugMessages TheDebugMessages;

// Using a template allows us to check message ID range at compile time.
/// \returns configured debugging level for the given message or defaultLevel
template <DebugMessageId id>
inline int
DebugMessageLevel(const int defaultLevel)
{
    static_assert(id > 0, "debugs() message ID must be positive");
    static_assert(id < DebugMessageCount, "debugs() message ID too large");
    return TheDebugMessages[id].currentLevel(defaultLevel);
}

/* convenience macros for calling DebugMessageLevel */
#define Critical(id) DebugMessageLevel<id>(DBG_CRITICAL)
#define Important(id) DebugMessageLevel<id>(DBG_IMPORTANT)
#define Dbg(id, defaultLevel) DebugMessageLevel<id>(defaultLevel)

#endif /* SQUID_DEBUG_MESSAGES_H */

#endif /* SQUID_DEBUG_H */

