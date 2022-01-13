/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTP_HEADEREDITOR_H
#define SQUID_HTTP_HEADEREDITOR_H

#include "base/RefCount.h"
#include "format/Format.h"
#include "http/forward.h"

class RegexPattern;
class SBuf;

namespace Http
{

/// an editor of (malformed) request headers
class HeaderEditor : public RefCountable
{
public:
    /// TODO: consider adding other commands (e.g., 'remove')
    enum class Command { replace };

    /// what fix() should do with the input string:
    ///	first: adjust only the first matched string (and ignore any further matches)
    /// each: adjust each matched string
    /// all: adjust only the first matched string (and signal the caller to delete any further matches)
    enum class CommandArgument { first, all, each };

    explicit HeaderEditor(ConfigParser &parser, const char *name);

    ~HeaderEditor();

    void parseOptions(ConfigParser &parser);

    /// \param input the request headers needing modification
    /// \returns the adjusted input according to the configured rules
    SBuf fix(const SBuf &input, const AccessLogEntryPointer &al);

    /// parses the regex group number
    static uint64_t ParseReGroupId(const char *);

    /// reproduces the configured squid.conf settings
    void dump(std::ostream &os) const;

private:
    bool compileRE(SBuf &, const int flags);
    void adjust(SBuf &input, RegexPattern &pattern);
    void applyFormat(SBuf &, RegexMatch *);
    void removeEmptyLines(SBuf &) const;

    // the corresponding configuration directive name
    const char *directiveName;
    Command command_; ///< the directive command
    CommandArgument commandArgument_; // the configured command's argument
    /// compiled representations of the configured list of regular expressions
    std::list<RegexPattern> patterns_;
    Format::Format *format_ = nullptr;
    ACLList *aclList = nullptr;
    // for debugging only
    SBuf formatString_;
    AccessLogEntryPointer al_;
    bool normalize_ = true;
};

} // namespace Http

#endif

