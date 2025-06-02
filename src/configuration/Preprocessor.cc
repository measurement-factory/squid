/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "cache_cf.h"
#include "ConfigOption.h"
#include "configuration/Preprocessor.h"
#include "configuration/Smooth.h"
#include "debug/Messages.h"
#include "debug/Stream.h"
#include "fatal.h"
#include "ipc/Kids.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "tools.h"

#if HAVE_GLOB_H
#include <glob.h>
#endif

namespace Configuration {

/// summarizes the difference between two sequences of configuration directives
class Diff
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

static std::ostream &
operator <<(std::ostream &os, const Diff &diff)
{
    diff.print(os);
    return os;
}

/// modes supported by reconfiguration directive
enum class ReconfigurationMode { harsh, smooth, smoothOrHarsh };

/// whether current/applied configuration dictates harsh reconfiguration (or we
/// have not applied any configuration yet -- the initial configuration is
/// necessarily "harsh")
/// \sa HarshReconfigurationBanned()
static bool
HarshReconfigurationRequired()
{
    return !Config.reconfigurationMode || *Config.reconfigurationMode == ReconfigurationMode::harsh;
}

/// whether current/applied configuration dictates smooth reconfiguration
/// \sa HarshReconfigurationRequired()
static bool
HarshReconfigurationBanned()
{
    return Config.reconfigurationMode && *Config.reconfigurationMode == ReconfigurationMode::smooth;
}

} // namespace Configuration

/// Determines whether the given squid.conf character is a token-delimiting
/// space character according to squid.conf preprocessor grammar. That grammar
/// only recognizes two space characters: ASCII SP and HT. Unlike isspace(3),
/// this function is not sensitive to locale(1) and does not classify LF, VT,
/// FF, and CR characters as token-delimiting space. However, some squid.conf
/// directive-specific parsers still define space based on isspace(3).
static bool
IsSpace(const char ch)
{
    return CharacterSet::WSP[ch];
}

/// the address of the first character in the given c-string for which IsSpace()
/// is false; that character may be a c-string NUL terminator character
static const char *
skipLeadingSpace(const char *s)
{
    while (IsSpace(*s))
        ++s;

    return s;
}

/// extracts all leading space characters (if any)
/// \returns whether at least one character was extracted
static bool
SkipOptionalSpace(Parser::Tokenizer &tk)
{
    return tk.skipAll(CharacterSet::WSP);
}

/// extracts all (and at least one) characters matching tokenChars surrounded by optional space
static SBuf
ExtractToken(const char * const description, Parser::Tokenizer &tk, const CharacterSet &tokenChars)
{
    const auto savedTk = tk;

    (void)SkipOptionalSpace(tk);

    SBuf token;
    if (tk.prefix(token, tokenChars)) {
        (void)SkipOptionalSpace(tk);
        return token;
    }

    tk = savedTk;
    throw TextException(ToSBuf("cannot find ", description, " near ", tk.remaining()), Here());
}

/// extracts an operand of a preprocessor condition
static SBuf
ExtractOperand(const char * const description, Parser::Tokenizer &tk)
{
    static const auto operandChars = (CharacterSet::ALPHA + CharacterSet::DIGIT).add('-').add('+').rename("preprocessor condition operand");
    return ExtractToken(description, tk, operandChars);
}

/// extracts an operator of a preprocessor condition
static SBuf
ExtractOperator(const char * const description, Parser::Tokenizer &tk)
{
    static const auto operatorChars = CharacterSet("preprocessor condition operator", "<=>%/*^!");
    return ExtractToken(description, tk, operatorChars);
}

/// throws on non-empty remaining input
static void
RejectTrailingGarbage(const char * const parsedInputDescription, const SBuf &parsedInput, const Parser::Tokenizer &tk)
{
    if (!tk.atEnd()) {
        throw TextException(ToSBuf("found trailing garbage after parsing ",
                                   parsedInputDescription, ' ', parsedInput, ": ",
                                   tk.remaining()), Here());
    }
}

/// interprets the given raw string as a signed integer (in decimal, hex, or
/// octal base per Parser::Tokenizer::int64())
static int64_t
EvalNumber(const SBuf &raw)
{
    auto numberParser = Parser::Tokenizer(raw);
    int64_t result = 0;
    if (!numberParser.int64(result, 0, true))
        throw TextException(ToSBuf("malformed integer near ", raw), Here());
    RejectTrailingGarbage("integer", raw, numberParser);
    return result;
}

/// IsIfStatementOpening() helper that interprets input prefix as a preprocessor condition
static bool
EvalBoolExpr(Parser::Tokenizer &tk)
{
    const auto operand = ExtractOperand("preprocessor condition", tk);

    static const auto keywordTrue = SBuf("true");
    if (operand == keywordTrue)
        return true;

    static const auto keywordFalse = SBuf("false");
    if (operand == keywordFalse)
        return false;

    const auto lhs = operand;

    const auto op = ExtractOperator("equality sign in an equality condition", tk);
    static const auto keywordEqual = SBuf("=");
    if (op != keywordEqual)
        throw TextException(ToSBuf("expected equality sign (=) but got ", op), Here());

    const auto rhs = ExtractOperand("right-hand operand of an equality condition", tk);
    return EvalNumber(lhs) == EvalNumber(rhs);
}

/// interprets input as the first line of a preprocessor `if` statement
/// \returns std::nullopt if input does not look like an `if` statement
/// \returns `if` condition value if input is an `if` statement
static std::optional<bool>
IsIfStatementOpening(Parser::Tokenizer tk)
{
    // grammar: space* "if" space condition space* END
    (void)SkipOptionalSpace(tk);
    const auto keywordIf = SBuf("if");
    if (tk.skip(keywordIf) && SkipOptionalSpace(tk)) {
        const auto condition = tk.remaining();
        const auto result = EvalBoolExpr(tk);
        (void)SkipOptionalSpace(tk);
        RejectTrailingGarbage("preprocessor condition", condition, tk);
        return result;
    }

    // e.g., "iffy_error_responses on"
    return std::nullopt;
}

/// interprets input as an `else` or `endif` line of a preprocessor `if` statement
/// \returns false if input does not look like an `else` or `endif` line
static bool
IsIfStatementLine(const SBuf &keyword, Parser::Tokenizer tk)
{
    // grammar: space* keyword space* END
    (void)SkipOptionalSpace(tk);
    if (tk.skip(keyword)) {
        if (tk.atEnd())
            return true;

        if (SkipOptionalSpace(tk)) {
            RejectTrailingGarbage("preprocessor keyword", keyword, tk);
            return true;
        }
        // e.g., "elseif"
    }

    return false;
}

/// interprets input as an `include <files>` preprocessor directive
/// \returns std::nullopt if input does not look like an `include` statement
/// \returns `include` parameters if input is an `include` statement
static std::optional<SBuf>
IsIncludeLine(Parser::Tokenizer tk)
{
    // grammar: space* "include" space files space* END
    (void)SkipOptionalSpace(tk);
    const auto keywordInclude = SBuf("include");
    if (tk.skip(keywordInclude) && SkipOptionalSpace(tk)) {
        // for simplicity sake, we leave trailing space, if any, in the result
        return tk.remaining();
    }

    // e.g., "include_version_info allow all"
    return std::nullopt;
}

/// interprets input as an `configuration_includes_quoted_values` preprocessor directive
/// \returns std::nullopt if input does not look like an `configuration_includes_quoted_values` statement
/// \returns the `configuration_includes_quoted_values` parameter otherwise
static std::optional<SBuf>
IsIncludesQuotedValues(Parser::Tokenizer tk)
{
    (void)SkipOptionalSpace(tk);
    const auto keywordConfigurationIncludes = SBuf("configuration_includes_quoted_values");
    if (tk.skip(keywordConfigurationIncludes) && SkipOptionalSpace(tk))
        return tk.remaining();
    return std::nullopt;
}

/// Replaces all occurrences of macroName in buf with macroValue. When looking
/// for the next macroName occurrence, this one-scan algorithm does not revisit
/// previously scanned buf areas and does not visit replaced values.
static void
SubstituteMacro(SBuf &buf, const SBuf &macroName, const SBuf &macroValue)
{
    SBuf remainingInput = buf;
    buf.clear();
    while (!remainingInput.isEmpty()) {
        const auto pos = remainingInput.find(macroName);
        if (pos == SBuf::npos) {
            buf.append(remainingInput);
            return;
        }

        buf.append(remainingInput.substr(0, pos));
        buf.append(macroValue);
        remainingInput.chop(pos + macroName.length());
    }
}

/// expands all configuration ${macros} inside the given configuration line
static void
ProcessMacros(SBuf &buf)
{
    static const auto macroServiceName = SBuf("${service_name}");
    static const auto macroProcessName = SBuf("${process_name}");
    static const auto macroProcessNumber = SBuf("${process_number}");
    static const auto kidIdentifier = ToSBuf(KidIdentifier);
    SubstituteMacro(buf, macroServiceName, service_name);
    SubstituteMacro(buf, macroProcessName, TheKidName);
    SubstituteMacro(buf, macroProcessNumber, kidIdentifier);
}

Configuration::PreprocessedCfg::Pointer
Configuration::Preprocess(const char * const filename, const PreprocessedCfg::Pointer &previousCfg)
{
    debugs(3, 7, filename);
    Preprocessor pp;
    pp.process(filename);

    // to simplify, the code below assumes that process() errors cannot reach it
    pp.assessSmoothConfigurationTolerance(previousCfg);
    return pp.finalize();
}

/* Configuration::Component<Configuration::ReconfigurationMode*> */

/// converts the next squid.conf token to ReconfigurationMode
static Configuration::ReconfigurationMode
ParseReconfigurationMode(ConfigParser &parser)
{
    const auto name = parser.token("reconfiguration mode name");
    if (name.cmp("harsh") == 0)
        return Configuration::ReconfigurationMode::harsh;
    if (name.cmp("smooth") == 0)
        return Configuration::ReconfigurationMode::smooth;
    if (name.cmp("smooth-or-harsh") == 0)
        return Configuration::ReconfigurationMode::smoothOrHarsh;
    throw TextException(ToSBuf("unsupported reconfiguration mode: '", name, "'"), Here());
}

template <>
void
Configuration::Component<Configuration::ReconfigurationMode*>::Reset(ReconfigurationMode *&mode)
{
    delete mode;
    mode = nullptr;
}

template <>
void
Configuration::Component<Configuration::ReconfigurationMode*>::Parse(ReconfigurationMode *&raw, ConfigParser &parser)
{
    Reset(raw);
    raw = new ReconfigurationMode(ParseReconfigurationMode(parser));
}

template <>
void
Configuration::Component<Configuration::ReconfigurationMode*>::Print(std::ostream &os, ReconfigurationMode * const &mode, const char * const directiveName)
{
    os << directiveName << ' ';
    Assure(mode);
    switch (*mode) {
    case ReconfigurationMode::harsh:
        os << "harsh";
        break;
    case ReconfigurationMode::smooth:
        os << "smooth";
        break;
    case ReconfigurationMode::smoothOrHarsh:
        os << "smooth-or-harsh";
        break;
    }
    os << "\n";
}

template <>
void
Configuration::Component<Configuration::ReconfigurationMode*>::StartSmoothReconfiguration(SmoothReconfiguration &)
{
}

template <>
void
Configuration::Component<Configuration::ReconfigurationMode*>::FinishSmoothReconfiguration(SmoothReconfiguration &sr)
{
    // DEFAULT_IF_NONE removes the need to handle disappearing custom/explicit directive specially
    Assure(sr.freshConfig.hasDirective(SBuf("reconfiguration")));
}

template <>
void
Configuration::Component<Configuration::ReconfigurationMode*>::Reconfigure(SmoothReconfiguration &, Configuration::ReconfigurationMode *&mode, ConfigParser &parser)
{
    Assure(mode);
    *mode = ParseReconfigurationMode(parser); // if parsing fails, old mode is preserved
}

/* Configuration::PreprocessedCfg */

bool
Configuration::PreprocessedCfg::hasDirective(const SBuf &canonicalName) const
{
    return seenDirectives_.find(canonicalName) != seenDirectives_.end();
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
        throw TextException(ToSBuf("Found ", invalidLines_, " invalid configuration line(s)"), Here());
}

/// initiates processing of a directive that was generated by default
void
Configuration::Preprocessor::importDefaultDirective(const SBuf &whole)
{
    // This method logic mimics processFile(), but this method code is much
    // simpler because default directives do not support such preprocessing
    // features as #line directives, conditionals, and include statements.

    // TODO: Upgrade config_input_line to SBuf, eliminating code duplication
    // in ConfigParser::openDirective() together with truncation concerns.
    const auto copied = whole.copy(config_input_line, sizeof(config_input_line) - 1);
    config_input_line[copied] = '\0';

    config_lineno++;

    auto adjustable = whole;
    ProcessMacros(adjustable);
    processDirective(adjustable);
}

/// Handles configuration file with a given name, at a given inclusion depth.
/// Configuration include instructions (if any) trigger indirect recursion.
void
Configuration::Preprocessor::processFile(const char * const file_name, const size_t depth)
{
    FILE *fp = nullptr;
    const auto orig_cfg_filename = cfg_filename;
    const int orig_config_lineno = config_lineno;
    char *token = nullptr;
    int is_pipe = 0;

    debugs(3, Important(68), "Processing Configuration File: " << file_name << " (depth " << depth << ")");
    if (depth > 16) {
        fatalf("WARNING: can't include %s: includes are nested too deeply (>16)!\n", file_name);
        return;
    }

    if (file_name[0] == '!' || file_name[0] == '|') {
        fp = popen(file_name + 1, "r");
        is_pipe = 1;
    } else {
        fp = fopen(file_name, "r");
    }

    if (!fp) {
        int xerrno = errno;
        fatalf("Unable to open configuration file: %s: %s", file_name, xstrerr(xerrno));
    }

#if _SQUID_WINDOWS_
    setmode(fileno(fp), O_TEXT);
#endif

    SwitchToExternalInput(file_name, bool(is_pipe));

    memset(config_input_line, '\0', BUFSIZ);

    // sequential raw input lines merged to honor line continuation markers
    SBuf wholeLine;

    std::vector<bool> if_states;
    while (fgets(config_input_line, BUFSIZ, fp)) {
        ++config_lineno;

        if ((token = strchr(config_input_line, '\n')))
            *token = '\0';

        if ((token = strchr(config_input_line, '\r')))
            *token = '\0';

        // strip any prefix whitespace off the line.
        const char *p = skipLeadingSpace(config_input_line);
        if (config_input_line != p)
            memmove(config_input_line, p, strlen(p)+1);

        if (strncmp(config_input_line, "#line ", 6) == 0) {
            static char new_file_name[1024];
            static char *file;
            static char new_lineno;
            token = config_input_line + 6;
            new_lineno = strtol(token, &file, 0) - 1;

            if (file == token)
                continue;   /* Not a valid #line directive, may be a comment */

            while (*file && IsSpace(*file))
                ++file;

            if (*file) {
                if (*file != '"')
                    continue;   /* Not a valid #line directive, may be a comment */

                xstrncpy(new_file_name, file + 1, sizeof(new_file_name));

                if ((token = strchr(new_file_name, '"')))
                    *token = '\0';

                SwitchToExternalInput(new_file_name, false);
            }

            config_lineno = new_lineno;
        }

        if (config_input_line[0] == '#')
            continue;

        if (config_input_line[0] == '\0')
            continue;

        wholeLine.append(config_input_line);

        if (!wholeLine.isEmpty() && *wholeLine.rbegin() == '\\') {
            debugs(3, 5, "expecting line continuation after " << wholeLine);
            wholeLine.chop(0, wholeLine.length() - 1); // drop trailing backslash
            continue;
        }

        ProcessMacros(wholeLine);
        auto tk = Parser::Tokenizer(wholeLine);

        // (void)tk.skipAll(CharacterSet::WSP) is not necessary due to earlier skipLeadingSpace()
        (void)tk.skipAllTrailing(CharacterSet::WSP);

        debugs(3, (opt_parse_cfg_only?1:5), "Processing: " << tk.remaining());

        static const auto keywordElse = SBuf("else");
        static const auto keywordEndif = SBuf("endif");
        if (const auto condition = IsIfStatementOpening(tk)) {
            if_states.push_back(*condition); // store last if-statement meaning
        } else if (IsIfStatementLine(keywordEndif, tk)) {
            if (!if_states.empty())
                if_states.pop_back(); // remove last if-statement meaning
            else
                fatalf("'endif' without 'if'\n");
        } else if (IsIfStatementLine(keywordElse, tk)) {
            if (!if_states.empty())
                if_states.back() = !if_states.back();
            else
                fatalf("'else' without 'if'\n");
        } else if (if_states.empty() || if_states.back()) { // test last if-statement meaning if present
            /* Handle includes here */
            if (const auto files = IsIncludeLine(tk)) {
                processIncludedFiles(*files, depth + 1);
            } else if (const auto value = IsIncludesQuotedValues(tk)) {
                processIncludesQuotedValues(*value);
            } else {
                processDirective(wholeLine);
            }
        }

        wholeLine.clear();
    }
    if (!if_states.empty())
        fatalf("if-statement without 'endif'\n");

    if (is_pipe) {
        int ret = pclose(fp);

        if (ret != 0)
            fatalf("parseConfigFile: '%s' failed with exit code %d\n", file_name, ret);
    } else {
        fclose(fp);
    }

    cfg_filename = orig_cfg_filename;
    config_lineno = orig_config_lineno;
}

/// Parsers included configuration files identified by their filenames or glob
/// patterns and included at the given nesting level (a.k.a. depth).
/// For example, parses include files in `include /path/to/include/files/*.acl`.
/// \returns the number of errors (that did not immediately terminate parsing)
void
Configuration::Preprocessor::processIncludedFiles(const SBuf &paths, const size_t depth)
{
    Parser::Tokenizer tk(paths);
#if HAVE_GLOB
    glob_t globbuf;
    int i;
    memset(&globbuf, 0, sizeof(globbuf));
    while (auto path = NextWordWhileRemovingDoubleQuotesAndBackslashesInsideThem(tk)) {
        if (glob(path->c_str(), globbuf.gl_pathc ? GLOB_APPEND : 0, nullptr, &globbuf) != 0) {
            const auto xerrno = errno;
            throw TextException(ToSBuf("Unable to find configuration file: ", *path, ": ", xstrerr(xerrno)), Here());
        }
    }
    for (i = 0; i < (int)globbuf.gl_pathc; ++i) {
        processFile(globbuf.gl_pathv[i], depth);
    }
    globfree(&globbuf);
#else
    while (auto path = NextWordWhileRemovingDoubleQuotesAndBackslashesInsideThem(tk)) {
        processFile(path->c_str(), depth);
    }
#endif /* HAVE_GLOB */
}

void
Configuration::Preprocessor::processIncludesQuotedValues(const SBuf &input)
{
    includesQuotedValues_ = parseOnOff(input);
}

void
Configuration::Preprocessor::processDirective(const SBuf &rawWhole)
{
    try {
        return addDirective(PreprocessedDirective(rawWhole, includesQuotedValues_));
    } catch (...) {
        ++invalidLines_;
        debugs(3, DBG_CRITICAL, "ERROR: " << CurrentException <<
               Debug::Extra << "directive text: " << rawWhole <<
               Debug::Extra << "directive location: " << ConfigParser::CurrentLocation());
    }
}

void
Configuration::Preprocessor::assessSmoothConfigurationTolerance(const PreprocessedCfg::Pointer &previousCfg)
{
    if (smoothReconfigurationBan_)
        return; // already decided

    if (!previousCfg)
        return banSmoothReconfiguration("there is no previous configuration");

    // TODO: This check requires two reconfigurations to switch from harsh to
    // smooth reconfiguration. Can we do better?
    if (HarshReconfigurationRequired())
        return banSmoothReconfiguration("current configuration bans smooth reconfiguration");

    // we delayed this relatively expensive (and loud) check as much as possible
    if (const auto diff = findRigidChanges(previousCfg->rigidDirectives)) {
        debugs(3, DBG_IMPORTANT, "Found changes in rigid configuration directives" <<
               Debug::Extra << diff);
        return banSmoothReconfiguration("the rigid part of the config has changed");
    }

    // we found no reasons to ban smooth reconfiguration
}

Configuration::PreprocessedCfg::Pointer
Configuration::Preprocessor::finalize()
{
    cfg_->allowSmoothReconfiguration = !smoothReconfigurationBan_;
    cfg_->allowHarshReconfiguration = !HarshReconfigurationBanned();

    debugs(3, 3, "valid: " << cfg_->allDirectives.size() <<
           " rigid: " << cfg_->rigidDirectives.size() <<
           " pliable: " << cfg_->pliableDirectives.size() <<
           " allowSmoothReconfiguration: " << cfg_->allowSmoothReconfiguration <<
           " allowHarshReconfiguration: " << cfg_->allowHarshReconfiguration);
    Assure(!invalidLines_);
    return cfg_;
}

/// prevent smooth reconfiguration during the current (re)configuration attempt
void
Configuration::Preprocessor::banSmoothReconfiguration(const char *reason)
{
    if (!smoothReconfigurationBan_) {
        smoothReconfigurationBan_ = reason;
        const auto dbgLevel = HarshReconfigurationRequired() ? 2 : DBG_IMPORTANT;
        debugs(3, dbgLevel, "Avoiding smooth reconfiguration because " << reason);
    } else {
        debugs(3, 3, "also because " << reason);
    }
}

void
Configuration::Preprocessor::addDirective(const PreprocessedDirective &directive)
{
    debugs(3, 7, directive);
    cfg_->allDirectives.push_back(directive);
    auto &addedDirective = cfg_->allDirectives.back();

    const auto firstOccurrence = cfg_->seenDirectives_.emplace(addedDirective.metadata().canonicalName, addedDirective).second;
    if (!firstOccurrence && !directive.metadata().mayBeSeenMultipleTimes) {
        const auto &previousOccurrence = cfg_->seenDirectives_.at(directive.metadata().canonicalName);
        throw TextException(ToSBuf("unsupported duplicate configuration directive",
                                   Debug::Extra, "earlier directive with the same name (or alias): ", previousOccurrence),
                            Here());
    }

    auto &index = directive.metadata().supportsSmoothReconfiguration ? cfg_->pliableDirectives : cfg_->rigidDirectives;
    index.push_back(addedDirective);
}

/// whether the named directive has been preprocessed at least once
bool
Configuration::Preprocessor::sawDirective(const SBuf &canonicalName) const
{
    return cfg_->hasDirective(canonicalName);
}

Configuration::Diff
Configuration::Preprocessor::findRigidChanges(const PreprocessedCfg::SelectedDirectives &previous) const
{
    // We could detect multiple differences, but it is difficult to find a small
    // but still comprehensive diff (e.g., like Unix "diff" often does), and
    // finding one change is sufficient for our code to make the smooth
    // reconfiguration decision, so we stop at the first difference for now.
    Diff diff;

    auto previousPos = previous.begin();

    for (const auto rigidDirective: cfg_->rigidDirectives) {
        const auto &currentDir = rigidDirective.get();
        if (previousPos == previous.end()) {
            diff.noteAppearance(currentDir);
            return diff;
        }

        const auto &previousDir = *previousPos;
        if (currentDir.differsFrom(previousDir)) {
            diff.noteChange(previousDir, currentDir);
            return diff;
        }

        ++previousPos;
    }

    if (previousPos != previous.end()) {
        const auto &disappeared = *previousPos;
        diff.noteDisappearance(disappeared);
        return diff;
    }

    diff.noteLackOfChanges();
    return diff;
}

/* Configuration::Diff */

void
Configuration::Diff::noteChange(const PreprocessedDirective &oldD, const PreprocessedDirective &newD)
{
    assert(changes_.isEmpty());
    const auto diff = newD.differsFrom(oldD);
    if (diff.hasLook()) {
        changes_ = ToSBuf("directives or their order has changed:",
                          Debug::Extra, "old configuration had: ", oldD,
                          Debug::Extra, "new configuration has: ", newD);
    }
    if (diff.hasQuoting()) {
        if (!changes_.isEmpty())
            changes_.append(ToSBuf(Debug::Extra));
        changes_.append(ToSBuf("directive contexts have changed:",
                               Debug::Extra, "configuration directive: ", newD,
                               Debug::Extra, "old configuration context: configuration_includes_quoted_values: ", oldD.quoted(),
                               Debug::Extra, "new configuration context: configuration_includes_quoted_values: ", newD.quoted()));
    }
    assert(!changes_.isEmpty());
}

void
Configuration::Diff::noteAppearance(const PreprocessedDirective &newD)
{
    assert(changes_.isEmpty());
    changes_ = ToSBuf("new configuration has more directives:",
                      Debug::Extra, "the first new directive absent in the old configuration: ", newD);
}

void
Configuration::Diff::noteDisappearance(const PreprocessedDirective &oldD)
{
    assert(changes_.isEmpty());
    changes_ = ToSBuf("old configuration had more directives:",
                      Debug::Extra, "the first old directive absent in the new configuration: ", oldD);
}

void
Configuration::Diff::noteLackOfChanges()
{
    assert(changes_.isEmpty());
    debugs(3, 5, "rigid directives have not changed");
}

void
Configuration::Diff::print(std::ostream &os) const
{
    os << changes_;
}

/* Configuration::PreprocessedDirective */

Configuration::PreprocessedDirective::PreprocessedDirective(const SBuf &rawWhole, const bool isQuoted):
    whole_(rawWhole),
    location_(cfg_filename, config_lineno),
    quoted_(isQuoted)
{
    static const auto nameChars = CharacterSet::WSP.complement("directive name");

    Parser::Tokenizer tok(rawWhole);
    name_ = ExtractToken("directive name", tok, nameChars);
    parameters_ = tok.remaining(); // may be empty
    metadata_ = GetMetadata(name_);
}

Configuration::PreprocessedDirective::Diff
Configuration::PreprocessedDirective::differsFrom(const PreprocessedDirective &other) const
{
    // we do not ignore the difference in indentation/space, case, and such (for
    // now) because their definition/sensitivity is currently directive-specific
    Diff diff;
    if (parameters_ != other.parameters_)
        diff.setLook();
    if (quoted_ != other.quoted_)
        diff.setQuoting();
    return diff;
}

void
Configuration::PreprocessedDirective::Diff::setLook()
{
    scope_ |= Scope::look;
}
bool
Configuration::PreprocessedDirective::Diff::hasLook() const
{
    return (scope_ & Scope::look) == Scope::look;
}

void
Configuration::PreprocessedDirective::Diff::setQuoting()
{
    scope_ |= Scope::quoting;
}

bool
Configuration::PreprocessedDirective::Diff::hasQuoting() const
{
    return (scope_ & Scope::quoting) == Scope::quoting;
}

void
Configuration::PreprocessedDirective::print(std::ostream &os) const
{
    os << location_ << ": " << name_ << ' ' << parameters_;
}

void
Configuration::Location::print(std::ostream &os) const
{
    os << name_ << '(' << lineNo_ << ')';
}
