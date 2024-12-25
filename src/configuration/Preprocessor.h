/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CONFIGURATION_PREPROCESSOR_H
#define SQUID_SRC_CONFIGURATION_PREPROCESSOR_H

#include "configuration/forward.h"
#include "mem/PoolingAllocator.h"
#include "sbuf/Algorithms.h"
#include "sbuf/forward.h"

#include <deque>
#include <memory>
#include <unordered_set>

namespace Configuration {

/// input coordinates with line number precision
class Location
{
public:
    explicit Location(const SBuf &aName, const size_t aLineNo = 0): name_(aName), lineNo_(aLineNo) {}

    /// input source description (e.g., a file name or a shell command)
    const auto &name() const { return name_; }

    /// line offset within input source; the first input byte has line offset 1
    auto lineNo() const { return lineNo_; }

    /// change line within the same input source
    void jumpTo(const size_t aLineNo) { lineNo_ = aLineNo; }

    /// convenience wrapper implementing a jumpTo() the next line
    Location &operator ++() { ++lineNo_; return *this; }

    /// reports location using a compact format suitable for diagnostic messages
    void print(std::ostream &) const;

private:
    SBuf name_; ///< \copydoc name()
    size_t lineNo_; ///< \copydoc lineNo()
};

/// \copydoc Location::print()
inline
std::ostream&
operator <<(std::ostream &os, const Location &l)
{
    l.print(os);
    return os;
}

/// artifacts of successful preprocessing; Preprocess() result
class PreprocessedCfg: public RefCountable
{
public:
    using Pointer = RefCount<PreprocessedCfg>;

    using Directive = PreprocessedDirective;

    /// preprocessed configuration directives in configuration order
    using Directives = std::deque<Directive, PoolingAllocator<Directive> >;

    /// all successfully preprocessed directives
    Directives directives;
};

/// Processes Squid configuration up to (and excluding) parsing of individual
/// directives (each described as a NAME:... blob in cf.data.pre). Handles
/// includes, conditional configuration, and ${macros}. Generates default
/// directives.
class Preprocessor
{
public:
    Preprocessor();

    /// Provides configuration parser with a sequence of preprocessed
    /// directives, including various defaults.
    PreprocessedCfg::Pointer process(const char * const filename);

private:
    void processFile(const char *filename, size_t depth);
    void processIncludedFiles(const SBuf &paths, size_t depth);

    void importDefaultDirective(const SBuf &whole);
    void processDirective(const SBuf &rawWhole);
    void addDirective(const PreprocessedDirective &);
    bool sawDirective(const SBuf &name) const;

    /* methods below are defined in cf_parser.cci generated by cf_gen.cc */
    void processInitialDefaults();
    void processIfNoneDefaults();
    void processPostscriptumDefaults();

private:
    /// preprocessed configuration being built by this object
    PreprocessedCfg::Pointer cfg_;

    /// a collection of directives names with fast lookup
    using SeenNames = std::unordered_set<SBuf, std::hash<SBuf>, std::equal_to<SBuf>, PoolingAllocator<SBuf> >;
    /// directives names seen so far
    SeenNames seenDirectives_;

    /// The number of lines we could not preprocess so far. This counter
    /// includes, without limitation, directives with misspelled names and
    /// directives that are disabled in this particular Squid build.
    size_t invalidLines_ = 0;
};

/// a single preprocessed configuration directive (supported or otherwise)
class PreprocessedDirective
{
public:
    explicit PreprocessedDirective(const SBuf &aWhole);

    /// entire preprocessed directive configuration, starting from the name and
    /// ending with the last parameter (if any)
    const auto &whole() const { return whole_; }

    /// the first token on a directive line; never empty
    const SBuf &name() const { return name_; }

    /// (unfolded) directive line contents after the name prefix; may be empty
    const SBuf &parameters() const { return buf_; }

    const Location &location() const { return location_; }

    /// whether the other directive is similar to this one
    bool similarTo(const PreprocessedDirective &other) const;

    void print(std::ostream &) const;

private:
    // defined in cf_parser.cci generated by cf_gen.cc
    static bool ValidDirectiveName(const SBuf &);

    SBuf whole_; ///< \copydoc whole()
    SBuf name_; ///< \copydoc name()
    SBuf buf_; ///< \copydoc contents(); XXX: rename to parameters_
    Location location_; ///< where this directive was obtained from
};

/// Interprets Squid configuration up to (and excluding) parsing of individual
/// directives. Returns a sequence of directives to parse, including various
/// defaults. Does not affect current Squid configuration. Never returns nil.
PreprocessedCfg::Pointer Preprocess(const char *filename);

inline
std::ostream&
operator <<(std::ostream &os, const PreprocessedDirective &d)
{
    d.print(os);
    return os;
}

} // namespace Configuration

#endif /* SQUID_SRC_CONFIGURATION_PREPROCESSOR_H */

