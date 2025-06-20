/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FORMAT_FORMAT_H
#define SQUID_SRC_FORMAT_FORMAT_H

#include "base/RefCount.h"
#include "ConfigParser.h"
#include "log/forward.h"
#include "sbuf/SBuf.h"

/*
 * Squid configuration allows users to define custom formats in
 * several components.
 * - logging
 * - external ACL input
 * - deny page URL
 *
 * These enumerations and classes define the API for parsing of
 * format directives to define these patterns. Along with output
 * functionality to produce formatted buffers.
 */

class MemBuf;
class StoreEntry;

namespace Format
{

extern const SBuf Dash;

class Token;

// XXX: inherit from linked list
class Format
{
public:
    Format(const char *name);
    virtual ~Format();

    /* very inefficient parser, but who cares, this needs to be simple */
    /* First off, let's tokenize, we'll optimize in a second pass.
     * A token can either be a %-prefixed sequence (usually a dynamic
     * token but it can be an escaped sequence), or a string. */
    bool parse(const char *def);

    /// assemble the state information into a formatted line.
    void assemble(MemBuf &, const AccessLogEntryPointer &, int logSequenceNumber, const RecordTime &) const;

    /// dump this whole list of formats into the provided StoreEntry
    void dump(StoreEntry * entry, const char *directiveName, bool eol = true) const;

    /// print this single format tokens using squid.conf syntax
    /// \sa dump()
    void dumpDefinition(std::ostream &os) const;

    /// whether assemble() returns the same result regardless of the supplied transaction details
    bool isStatic() const;

    char *name;

    /// format configuration (using squid.conf logformat specification syntax)
    SBuf specs;

    Token *format;
    Format *next;
};

/// Compiles a single logformat %code expression into the given buffer.
/// Ignores any input characters after the expression.
/// \param start  where the logformat expression begins
/// \return the length of the parsed %code expression
size_t AssembleOne(const char *start, MemBuf &, const AccessLogEntryPointer &, const RecordTime &);

} // namespace Format

#endif /* SQUID_SRC_FORMAT_FORMAT_H */

