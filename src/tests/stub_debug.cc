/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * A stub implementation of the Debug.h API.
 * For use by test binaries which do not need the full context debugging
 *
 * Note: it doesn't use the STUB API as the functions defined here must
 * not abort the unit test.
 */
#include "squid.h"
#include "Debug.h"

#define STUB_API "debug.cc"
#include "tests/STUB.h"

char *Debug::debugOptions;
char *Debug::cache_log= NULL;
int Debug::rotateNumber = 0;
int Debug::Levels[MAX_DEBUG_SECTIONS];
int Debug::override_X = 0;
bool Debug::log_syslog = false;
void Debug::ForceAlert() STUB

void ResyncDebugLog(FILE *) STUB

FILE *
DebugStream()
{
    return stderr;
}

void
_db_rotate_log(void)
{}

static void
LogMessage(const std::string &message)
{
    if (Debug::Level() > DBG_IMPORTANT)
        return;

    if (!stderr)
        return;

    fprintf(stderr, "%s| %s\n",
            "stub time", // debugLogTime(squid_curtime),
            message.c_str());
}

bool
Debug::ErrChannelEnabled() STUB_RETVAL(false)

void Debug::SwanSong() STUB

void
Debug::parseOptions(char const *)
{}

Debug::Context *Debug::Current = nullptr;

Debug::Context::Context(const int aSection, const int aLevel):
    section(aSection),
    level(aLevel),
    sectionLevel(Levels[aSection]),
    upper(Current),
    forceAlert(false)
{
    buf.setf(std::ios::fixed);
    buf.precision(2);
}

std::ostringstream &
Debug::Start(const int section, const int level)
{
    Current = new Context(section, level);
    return Current->buf;
}

void
Debug::Finish()
{
    if (Current) {
        LogMessage(Current->buf.str());
        delete Current;
        Current = nullptr;
    }
}

std::ostream&
ForceAlert(std::ostream& s)
{
    return s;
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
        os << (label_ ? '=' : ' ');
        if (data_)
            os.write(data_, size_);
        else
            os << "[null]";
    }

    return os;
}

