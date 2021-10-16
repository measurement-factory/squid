/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CONFIGURATION_PREPROCESSOR_H
#define SQUID_SRC_CONFIGURATION_PREPROCESSOR_H

#include "configuration/forward.h"
#include "sbuf/Algorithms.h"
#include "sbuf/SBuf.h"

#include <deque>
#include <memory>
#include <unordered_set>

namespace Configuration {

/// artifacts of successful preprocessing; Preprocess() result
class PreprocessedCfg: public RefCountable
{
public:
    using Pointer = RefCount<const PreprocessedCfg>;

    using Directive = PreprocessedDirective;

    /// preprocessed configuration directives in configuration order
    using Directives = std::deque< /* const here XXX? */ Directive /* XXX: Pool */ >;

    /// pointers to preprocessed configuration directives in configuration order
    using DirectiveIndex = std::deque<const Directive */* XXX: Pool */ >;

    /// all successfully preprocessed directives
    Directives allDirectives;

    /// directives that the parser (i.e. the next processing stage) should see
    DirectiveIndex activeDirectives;

    DirectiveIndex rigidDirectives;

    bool allowPartialReconfiguration = false;
};

/// Interprets Squid configuration up to (and excluding) parsing of individual
/// directives. Returns a sequence of directives to parse, including various
/// defaults. Facilitates partial reconfiguration. Does not affect current Squid
/// configuration.
PreprocessedCfg::Pointer Preprocess(const char *filename, PreprocessedCfg::Pointer previousCfg);

class DirectivesDiff;

/// address of a configuration place (e.g., "/usr/etc/squid.conf, line 5")
class Location {
public:
    Location() = default;
    explicit Location(const SBuf &context, const size_t lastLine = 0): context_(context), lastLine_(lastLine) {}

    /// forget all previously stored information (if any)
    void reset() { *this = Location(); }

    /// change line number to any valid value (or just forget it)
    void resetLine(const size_t lastLine = 0) { lastLine_ = lastLine; }

    /// advance to the next line (including the very first line after reset)
    void nextLine() { resetLine(lastLine_ + 1); }

    // TODO: This method should not be needed/used in modern code.
    /// \returns raw c-string describing the current context
    const SBuf &fileName() const { return context_; }

    // TODO: This method should not be needed/used in modern code.
    /// \returns \copydoc lastLine_
    size_t lineNumber() const { return lastLine_; }

    void print(std::ostream &) const;

private:
    /// the name of a configuration file (or a similar source of directives)
    SBuf context_;

    /// the number of context lines above (and inside) this place (or 0)
    size_t lastLine_ = 0;
};

// TODO: Move to Preprocessor.cc together with its diff-reducing methods in cache_cf.cc.
/// major Preprocess() implementation steps
class Preprocessor
{
public:
    using Directive = PreprocessedDirective;

    Preprocessor();
    ~Preprocessor();

    /// preprocess all configuration directives, including various defaults
    void process(const char *filename);

    /// decide whether to allow or ban partial reconfiguration support
    void assessPartialConfigurationTolerance(PreprocessedCfg::Pointer previousCfg);

    /// export preprocessing artifacts for external/parser consumption
    PreprocessedCfg::Pointer finalize();

    /// preprocessed configuration directives in configuration order
    using Directives = std::deque<Directive /* XXX: Pool */ >;

    /// pointers to preprocessed configuration directives in configuration order
    using DirectiveIndex = std::deque<const Directive */* XXX: Pool */ >;

private:
    static bool ValidDirectiveName(const SBuf &name);

    void resetContext(const Location &);
    void resetContextLine(const size_t);
    void advanceContext();
    void closeContext();

    void processInitialDefaults();
    void processIfNoneDefaults();
    void processPostscriptumDefaults();

    void processFile(const char *filename, size_t depth);
    void processIncludedFiles(char *filenameBuffer, size_t depth);
    void processUnfoldedLine(const SBuf &line);
    void addDirective(const SBuf &name, const SBuf &cfg);
    void banPartialReconfiguraiton(const char *reason);

    bool sawDirective(const char *name) const;

    void default_line(const char *s);

    DirectivesDiff findRigidChanges(const DirectiveIndex &previous) const;

    /// preprocessed configuration being built by this object
    RefCount<PreprocessedCfg> cfg_;

    /// a collection of directives names with fast lookup
    using SeenNames = std::unordered_set<SBuf /* Pool? */>;
    /// directives names seen so far
    SeenNames seenDirectives_;

    /// address of the currently preprocessed directive
    Location currentLocation_;

    /// The number of lines we could not preprocess so far. This counter
    /// includes, without limitation, directives with misspelled names and
    /// directives that are disabled in this particular Squid build.
    size_t invalidLines_ = 0;

    /// \copydoc doingPartialReconfiguration()
    const char *partialReconfigurationBan_ = nullptr; // string literal
    // Optional<bool> partialReconfigurationDecision_;
};

/// a single preprocessed configuration directive (supported or otherwise)
class PreprocessedDirective
{
public:
    /// \param cfg \copydoc buf_
    PreprocessedDirective(const Location &, const SBuf &cfg);

    /// where this directive was found
    const Location &location() const { return location_; }

    /// whether the other directive is similar to this one
    bool similarTo(const PreprocessedDirective &other) const;

    void print(std::ostream &) const;

    /// a throw-away/editable buffer
    using EditableBuf = std::unique_ptr<char[]>;

    /// a copy of the entire configuration in a throw-away/editable buffer
    EditableBuf editableBuf() const;

private:
    /// the source of this directive
    Location location_;

    /// the entire preprocessed configuration directive
    SBuf buf_;
};

/// forgets globally-stored(XXX) configuration preprocessing/parsing location
void ResetLocation();

/// syncs globally-stored(XXX) configuration preprocessing/parsing location
void ResetLocation(const Location &);

} // namespace Configuration

inline
std::ostream&
operator <<(std::ostream &os, const Configuration::PreprocessedDirective &d)
{
    d.print(os);
    return os;
}

inline
std::ostream&
operator <<(std::ostream &os, const Configuration::Location &l)
{
    l.print(os);
    return os;
}

#endif /* SQUID_SRC_CONFIGURATION_PREPROCESSOR_H */

