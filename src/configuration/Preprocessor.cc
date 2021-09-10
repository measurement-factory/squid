/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "ConfigParser.h" // TODO: Check whether this is needed
#include "configuration/Preprocessor.h"
#include "Debug.h"
#include "SquidConfig.h"
#include "sbuf/Stream.h"
#include "parser/Tokenizer.h"

namespace Configuration {

/// summarizes the difference between two sequences of configuration directives
class DirectivesDiff
{
public:
    /// whether the directive sequences differ
    explicit operator bool() const { return changes_.length(); }

    /// The directive from the old sequence is different from the same-position
    /// directive in the new sequence.
    void noteChange(const PreprocessedDirective &oldD, const PreprocessedDirective &newD);
    /// the new sequence has at least one extra directive
    void noteAppearance(const PreprocessedDirective &newD);
    /// the old sequence has at least one extra directive
    void noteDisappearance(const PreprocessedDirective &oldD);
    /// the old directive sequence has not changed
    void noteLackOfChanges();

    /// reports the details of the difference
    void print(std::ostream &) const;

private:
    /// a summary of the key differences (or an empty string if there are none)
    SBuf changes_;
};

} // namespace Configuration

inline static
std::ostream&
operator <<(std::ostream &os, const Configuration::DirectivesDiff &diff)
{
    diff.print(os);
    return os;
}

Configuration::PreprocessedCfg::Pointer
Configuration::Preprocess(const char * const filename, const PreprocessedCfg::Pointer previousCfg)
{
    debugs(3, 7, filename);
    Preprocessor pp;
    pp.process(filename);
    pp.assessPartialConfigurationTolerance(previousCfg);
    return pp.finalize();
}

/* Configuration::Preprocessor */

Configuration::Preprocessor::Preprocessor():
    cfg_(new PreprocessedCfg())
{
}

void
Configuration::Preprocessor::process(const char * const filename)
{
    debugs(3, DBG_PARSE_NOTE(2), "preprocessing defaults and " << filename);
    processInitialDefaults();
    processFile(filename, 0);
    processIfNoneDefaults();
    processPostscriptumDefaults();

    if (invalidLines_)
        throw TextException(ToSBuf("saw ", invalidLines_, " invalid configuration line(s)"), Here());
}

void
Configuration::Preprocessor::assessPartialConfigurationTolerance(const PreprocessedCfg::Pointer previousCfg)
{
    if (partialReconfigurationBan_)
        return; // already decided

    if (!previousCfg)
        return banPartialReconfiguraiton("there is no previous configuration");

    // after the above confirms that Squid has set this flag already
    if (!Config.onoff.smooth_reconfiguration)
        return banPartialReconfiguraiton("smooth_reconfiguration off");

    if (const auto diff = findRigidChanges(previousCfg->rigidDirectives)) {
        debugs(3, DBG_IMPORTANT, "Found changes in rigid configuration directives: " << diff);
        return banPartialReconfiguraiton("the rigid part of the config has changed");
    }

    // probably OK to do partial reconfiguration
}

Configuration::PreprocessedCfg::Pointer
Configuration::Preprocessor::finalize()
{
    const auto allowPartialReconfiguration = !partialReconfigurationBan_;
    cfg_->allowPartialReconfiguration = allowPartialReconfiguration;
    if (allowPartialReconfiguration) {
        // cfg_->activeDirectives is ready for use
    } else {
        cfg_->activeDirectives.resize(0);
        for (const auto &directive: cfg_->allDirectives)
            cfg_->activeDirectives.emplace_back(&directive);
    }
    debugs(3, 3, "valid: " << cfg_->allDirectives.size() <<
           " rigid: " << cfg_->rigidDirectives.size() <<
           " active: " << cfg_->activeDirectives.size() <<
           " pliable: " << (cfg_->allDirectives.size() - cfg_->rigidDirectives.size()) <<
           " invalid: " << invalidLines_ <<
           " allowPartialReconfiguration: " << cfg_->allowPartialReconfiguration);
    assert(!invalidLines_);
    return cfg_;
}

/// prevent partial reconfiguration during the current (re)configuration attempt
void
Configuration::Preprocessor::banPartialReconfiguraiton(const char *reason)
{
    if (!partialReconfigurationBan_) {
        partialReconfigurationBan_ = reason;
        const auto dbgLevel = Config.onoff.smooth_reconfiguration ? DBG_IMPORTANT : 2;
        debugs(3, dbgLevel, "Avoiding smooth_reconfiguration because " << reason);
    } else {
        debugs(3, 3, "also because " << reason);
    }
}

void
Configuration::Preprocessor::processUnfoldedLine(const SBuf &line)
{
    static const auto spaceChars = CharacterSet("space", " \t\n\r");
    static const auto nameChars = spaceChars.complement("name");

    Parser::Tokenizer tok(line);

    (void)tok.skipAll(spaceChars); // tolerate indentation and such
    if (tok.atEnd())
        return; // a directive-free and comment-free line
    if (tok.skip('#'))
        return; // a directive-free line with a comment

    const auto cfg = tok.remaining();

    SBuf name;
    const auto foundName = tok.prefix(name, nameChars);
    assert(foundName); // or we would have quit above

    if (ValidDirectiveName(name))
        return addDirective(name, cfg);

    banPartialReconfiguraiton("saw an invalid configuration directive");
    ++invalidLines_;
    debugs(3, DBG_CRITICAL, ConfigParser::CurrentLocation() <<
           ": ERROR: unrecognized configuration directive name: " << name);
}

void
Configuration::Preprocessor::addDirective(const SBuf &name, const SBuf &directiveCfg)
{
    // TODO: Use std::reference_wrapper instead of Directive pointers.

    debugs(3, 5, directiveCfg);
    cfg_->allDirectives.emplace_back(name, directiveCfg);
    seenDirectives_.emplace(name);

    // TODO: This should become an cf.data.pre Entry method.
    static const SBuf pliableName("acl");
    auto &index = (name == pliableName) ? cfg_->activeDirectives : cfg_->rigidDirectives;
    index.emplace_back(&cfg_->allDirectives.back());
}

bool
Configuration::Preprocessor::sawDirective(const char * const name) const
{
    const SBuf lookup(name); // XXX: Convert processIfNoneDefaults() to use SBuf
    return seenDirectives_.find(lookup) != seenDirectives_.end();
}

Configuration::DirectivesDiff
Configuration::Preprocessor::findRigidChanges(const DirectiveIndex &previous) const
{
    // We could detect multiple differences, but it is difficult to find a small
    // but still comprehensive diff (e.g., like "diff" often does) and finding
    // one change is sufficient for our code to make the smooth reconfiguration
    // decision, so we stop at the first difference for now.
    DirectivesDiff diff;

    auto previousPos = previous.begin();

    for (const auto currentDir: cfg_->rigidDirectives) {
        assert(currentDir);

        if (previousPos == previous.end()) {
            diff.noteAppearance(*currentDir);
            return diff;
        }

        const auto previousDir = *previousPos;
        assert(previousDir);
        if (!currentDir->similarTo(*previousDir)) {
            diff.noteChange(*previousDir, *currentDir);
            return diff;
        }

        ++previousPos;
    }

    if (previousPos != previous.end()) {
        const auto disappeared = *previousPos;
        assert(disappeared);
        diff.noteDisappearance(*disappeared);
        return diff;
    }

    diff.noteLackOfChanges();
    return diff;
}

/* Configuration::DirectivesDiff */

void
Configuration::DirectivesDiff::noteChange(const PreprocessedDirective &oldD, const PreprocessedDirective &newD)
{
    assert(changes_.isEmpty());
    changes_ = ToSBuf("directives or their order have changed:",
                      Debug::Extra, "old configuration has: ", oldD,
                      Debug::Extra, "new configuration has: ", newD);
}

void
Configuration::DirectivesDiff::noteAppearance(const PreprocessedDirective &newD)
{
    assert(changes_.isEmpty());
    changes_ = ToSBuf("new configuration has more directives:",
                      Debug::Extra, "the first directive missing from the old configuration: ", newD);
}

void
Configuration::DirectivesDiff::noteDisappearance(const PreprocessedDirective &oldD)
{
    assert(changes_.isEmpty());
    changes_ = ToSBuf("old configuration had more directives:",
                      Debug::Extra, "the first directive missing from the new configuration: ", oldD);
}

void
Configuration::DirectivesDiff::noteLackOfChanges()
{
    assert(changes_.isEmpty());
}

void
Configuration::DirectivesDiff::print(std::ostream &os) const
{
    os << changes_;
}

/* Configuration::PreprocessedDirective */

bool
Configuration::PreprocessedDirective::similarTo(const PreprocessedDirective &other) const
{
    // we do not ignore the difference in indentation/space, case, and such (for
    // now) because their definition/sensitivity is currently directive-specific
    return buf_ == other.buf_;
}

Configuration::PreprocessedDirective::EditableBuf
Configuration::PreprocessedDirective::editableBuf() const
{
    const auto unterminatedLength = buf_.length();
    EditableBuf buf(new char[unterminatedLength+1]);
    memcpy(buf.get(), buf_.rawContent(), unterminatedLength);
    buf[unterminatedLength] = '\0';
    return buf;
}

void
Configuration::PreprocessedDirective::print(std::ostream &os) const
{
    os << buf_;
}
