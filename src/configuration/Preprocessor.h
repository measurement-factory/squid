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


/// artifacts of a successful preprocessing step
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

PreprocessedCfg::Pointer Preprocess(const char *filename, PreprocessedCfg::Pointer previousCfg);

class DirectivesDiff;

// TODO: Move to Preprocessor.h
/// Interprets Squid configuration up to (and excluding) parsing of individual
/// directives. Provides configuration parser with a sequence of directives to
/// parse, including various defaults. Facilitates partial reconfiguration.
/// Preprocessor operations do not affect current Squid configuration.
class Preprocessor
{
public:
    using Directive = PreprocessedDirective;

    Preprocessor();

    // TODO: Describe.
    void process(const char *filename);

    void assessPartialConfigurationTolerance(PreprocessedCfg::Pointer previousCfg);

    PreprocessedCfg::Pointer finalize();

    /// preprocessed configuration directives in configuration order
    using Directives = std::deque<Directive /* XXX: Pool */ >;

    /// pointers to preprocessed configuration directives in configuration order
    using DirectiveIndex = std::deque<const Directive */* XXX: Pool */ >;

private:
    static bool ValidDirectiveName(const SBuf &name);

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
    PreprocessedDirective(const SBuf & /*XXX*/, const SBuf &cfg): buf_(cfg) {}

    /// the first token on a directive line
    SBuf name() const;

    /// whether the other directive is similar to this one
    bool similarTo(const PreprocessedDirective &other) const;

    void print(std::ostream &) const;

    /// a throw-away/editable buffer
    using EditableBuf = std::unique_ptr<char[]>;

    /// a copy of the entire configuration in a throw-away/editable buffer
    EditableBuf editableBuf() const;

private:
    /// entire preprocessed configuration
    SBuf buf_;
};

} // namespace Configuration

inline
std::ostream&
operator <<(std::ostream &os, const Configuration::PreprocessedDirective &d)
{
    d.print(os);
    return os;
}

#endif /* SQUID_SRC_CONFIGURATION_PREPROCESSOR_H */

