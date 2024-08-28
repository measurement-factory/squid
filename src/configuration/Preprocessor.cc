/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "cache_cf.h"
#include "configuration/Preprocessor.h"
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

/// updates cfg_filename global given raw configuration file specs that may
/// include pipelining instructions
static void
SetConfigFilename(char const *file_name, bool is_pipe)
{
    if (is_pipe)
        cfg_filename = file_name + 1;
    else
        cfg_filename = file_name;
}

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

/* Configuration::Preprocessor */

int
Configuration::Preprocessor::process(const char * const filename)
{
    debugs(3, DBG_PARSE_NOTE(2), "preprocessing defaults and " << filename);
    processInitialDefaults();
    const auto unrecognizedDirectives = processFile(filename, 0);
    processIfNoneDefaults();
    processPostscriptumDefaults();
    return unrecognizedDirectives;
}

/// initiates processing of a directive that was generated by default
void
Configuration::Preprocessor::importDefaultDirective(const char * const raw)
{
    SBuf directive(raw);
    ProcessMacros(directive);
    xstrncpy(config_input_line, directive.c_str(), sizeof(config_input_line));
    config_lineno++;
    parse_line(directive);
}

/// Handles configuration file with a given name, at a given inclusion depth.
/// Configuration include instructions (if any) trigger indirect recursion.
int
Configuration::Preprocessor::processFile(const char * const file_name, const size_t depth)
{
    FILE *fp = nullptr;
    const char *orig_cfg_filename = cfg_filename;
    const int orig_config_lineno = config_lineno;
    char *token = nullptr;
    int err_count = 0;
    int is_pipe = 0;

    debugs(3, Important(68), "Processing Configuration File: " << file_name << " (depth " << depth << ")");
    if (depth > 16) {
        fatalf("WARNING: can't include %s: includes are nested too deeply (>16)!\n", file_name);
        return 1;
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

    SetConfigFilename(file_name, bool(is_pipe));

    memset(config_input_line, '\0', BUFSIZ);

    config_lineno = 0;

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

                SetConfigFilename(new_file_name, false);
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
                err_count += processIncludedFiles(*files, depth + 1);
            } else {
                try {
                    if (!parse_line(wholeLine)) {
                        debugs(3, DBG_CRITICAL, "ERROR: unrecognized directive near '" << wholeLine << "'" <<
                               Debug::Extra << "directive location: " << ConfigParser::CurrentLocation());
                        ++err_count;
                    }
                } catch (...) {
                    // fatal for now
                    debugs(3, DBG_CRITICAL, "ERROR: configuration failure: " << CurrentException);
                    self_destruct();
                }
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

    SetConfigFilename(orig_cfg_filename, false);
    config_lineno = orig_config_lineno;

    return err_count;
}

/// Parsers included configuration files identified by their filenames or glob
/// patterns and included at the given nesting level (a.k.a. depth).
/// For example, parses include files in `include /path/to/include/files/*.acl`.
/// \returns the number of errors (that did not immediately terminate parsing)
int
Configuration::Preprocessor::processIncludedFiles(const SBuf &paths, const size_t depth)
{
    int error_count = 0;
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
        error_count += processFile(globbuf.gl_pathv[i], depth);
    }
    globfree(&globbuf);
#else
    while (auto path = NextWordWhileRemovingDoubleQuotesAndBackslashesInsideThem(tk)) {
        error_count += processFile(path->c_str(), depth);
    }
#endif /* HAVE_GLOB */
    return error_count;
}

