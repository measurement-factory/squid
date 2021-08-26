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

/// represents an editor for malformed request headers
class HeaderEditor : public RefCountable
{
public:
    /// TODO: consider adding other commands (e.g., 'remove')
    enum class Command { replace };

    /// what fix() should do with the input string:
    ///	first: fix only the first matched string (and ignore any further matches)
    /// each: fix each matched string
    /// all: fix only the first matched string (and signal the caller to delete any further matches)
    enum class CommandArgument { first, all, each };

    explicit HeaderEditor(ConfigParser &parser, const char *description);

    ~HeaderEditor();

    void parseOptions(ConfigParser &parser);

    /// Attempts to match the input string and returns a new string on success.
    /// \param fieldStart the start of the input string. On successful match,
    /// the address of the new string begginning is copied to the location referenced by fieldStart.
    /// \param fieldEnd the end of the input string. On successful match,
    /// the address of the new string ending (the termination character) is copied to the
    /// location referenced by fieldEnd.
    /// The returned values point to an internal storage whose contents
    /// remain unchanged only until the next call.
    SBuf fix(const SBuf &input, const AccessLogEntryPointer &al);

    /// parses the regex group number
    static uint64_t ParseReGroupId(const char *);

    /// reproduces the configured squid.conf settings
    void dump(std::ostream &os) const;

private:
    bool compileRE(SBuf &, const int flags);
    void applyOne(SBuf &input, RegexPattern &pattern);
    void applyAll(SBuf &input, RegexPattern &pattern);
    void applyEach(SBuf &input, RegexPattern &pattern);

    const char *description_;
    Command command_;
    CommandArgument commandArgument_;
    std::list<RegexPattern> patterns_;
    Format::Format *format_ = nullptr;
    ACLList *aclList = nullptr;
    int matchedCount_ = 0;
    // for debugging only
    SBuf formatString_;
    AccessLogEntryPointer al_;
};

} // namespace Http

#endif

