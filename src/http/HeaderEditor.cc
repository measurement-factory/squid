/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/Gadgets.h"
#include "acl/Tree.h"
#include "acl/FilledChecklist.h"
#include "base/RegexPattern.h"
#include "ConfigOption.h"
#include "format/Format.h"
#include "http/HeaderEditor.h"
#include "MemBuf.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

#include "rfc1738.h"

#include <map>

/// the maximum regex groups supported by the editor
static const int ReGroupMax = 10;

typedef std::map<SBuf, Http::HeaderEditor::CommandArgument> CommandArgumentMap;
static const CommandArgumentMap CommandArguments =
{
    {SBuf("first"), Http::HeaderEditor::CommandArgument::first},
    {SBuf("all"), Http::HeaderEditor::CommandArgument::all},
    {SBuf("each"), Http::HeaderEditor::CommandArgument::each}
};

static SBuf
CommandArgumentString(const Http::HeaderEditor::CommandArgument commandArgument)
{
    for (const auto p: CommandArguments) {
        if (p.second == commandArgument)
            return p.first;
    }
    return SBuf();
}

static bool
IsEmptyLine(SBuf &line)
{
    static auto pattern = RegexPattern(REG_EXTENDED, "^[ \t\r]*\n");
    static bool compiled = false;
    if (!compiled) {
        compiled = true;
        regex_t comp;
        (void)regcomp(&comp, pattern.c_str(), pattern.flags);
        pattern.regex = comp;
    }
    static RegexMatch match(ReGroupMax);
    return pattern.match(line.c_str(), match);
}

/// removes empty lines (with leading separators, if any) from the buffer
static SBuf
RemoveEmptyLines(SBuf &buf)
{
    SBuf result;
    SBuf::size_type prevPos = 0;
    SBuf::size_type pos = buf.find('\n');
    Must(pos != SBuf::npos);
    while ((pos = buf.find('\n', prevPos)) != SBuf::npos) {
        auto line = buf.substr(prevPos, pos-prevPos+1); // including '\n'
        if (!IsEmptyLine(line))
            result.append(line);
        prevPos = pos+1;
    }
    return result;
}

/// \returns header without its separator, which is either LF or CRLF
static SBuf
RemoveHeaderSeparator(const SBuf &input, SBuf &separator)
{
    Must(input.length());
    auto last = input.rbegin();
    Must(*last == '\n');
    const auto separatorLength = (input.length() > 1 && *(++last) == '\r') ? 2 : 1;
    separator = input.substr(input.length() - separatorLength);
    return input.substr(0, input.length() - separatorLength);
}
    
Http::HeaderEditor::HeaderEditor(ConfigParser &parser)
{
    parseOptions(parser);
}

Http::HeaderEditor::~HeaderEditor()
{
    aclDestroyAclList(&aclList);
    delete format_;
}

// TODO: resolve code duplication with acl/RegexData.cc
/// fills patterns_ with compiled regular expressions
bool
Http::HeaderEditor::compileRE(SBuf &str, const int flags)
{
    regex_t comp;
    if (const auto errcode = regcomp(&comp, str.c_str(), flags)) {
        char errbuf[256];
        regerror(errcode, &comp, errbuf, sizeof errbuf);
        throw TextException(ToSBuf("Invalid regular expression: ", errbuf), Here());
    }
    patterns_.emplace_back(flags, str.c_str());
    patterns_.back().regex = comp;
    return true;
}

SBuf
Http::HeaderEditor::fix(const SBuf &input, ACLFilledChecklist &checkList)
{
    if (aclList && !checkList.fastCheck(aclList).allowed())
        return input;

    al_ = checkList.al;

    SBuf separator;
    auto output = RemoveHeaderSeparator(input, separator);

    for (auto &pattern : patterns_) {
        if (pattern.match(output.c_str()))
            adjust(output, pattern);
    }

    output.append(separator);
    return output;
}

/// constructs a string based on the configured logformat rules and matched regular expressions
void
Http::HeaderEditor::applyFormat(SBuf &line, RegexMatch *match)
{
    static MemBuf mb;
    mb.reset();
    ::Format::Format::AssembleParams params;
    params.headerEditMatch = match;
    format_->assemble(mb, al_, &params);
    line.append(mb.content(), mb.contentSize());
}

/// Matches the input buffer with the compiled regex and replaces each
/// match with the corresponding formatted string.
void
Http::HeaderEditor::adjust(SBuf &input, RegexPattern &pattern)
{
    auto s = input.c_str();
    SBuf result;
    SBuf formattedLine;
    RegexMatch regexMatch(ReGroupMax);
    bool fixedOnce = false; // whether at least one replacement has been done

    while (pattern.match(s, regexMatch)) {
        result.append(s, regexMatch.startOffset());
        if (commandArgument_ != CommandArgument::all || !fixedOnce)
            applyFormat(formattedLine, &regexMatch);
        s += regexMatch.endOffset();
        auto nextLineStart = strchr(s, '\n');
        Must(nextLineStart);
        nextLineStart++;
        formattedLine.append(s, nextLineStart - s);
        fixedOnce = true;
        result.append(RemoveEmptyLines(formattedLine));
        s = nextLineStart;
        if (commandArgument_ == CommandArgument::first)
            break;
        formattedLine.clear();
        regexMatch.clear();
    }
    result.append(s);
    input = result;
}

uint64_t
Http::HeaderEditor::ParseReGroupId(const SBuf &str)
{
    auto tok = Parser::Tokenizer(str);
    int64_t id = 0;
    if (!tok.int64(id, 10, false))
        throw TexcHere("malformed regex group ID");
    return static_cast<uint64_t>(id);
}

const char *
UnescapeXXX(SBuf &buf)
{
    static char unescaped[256];
    SBuf::size_type upto = buf.copy(unescaped, sizeof(unescaped)-1);
    unescaped[upto]='\0';
    rfc1738_unescape(unescaped);
    return unescaped;
}

void
Http::HeaderEditor::parseOptions(ConfigParser &parser)
{
    static const SBuf reNs("re");
    static const SBuf lfNs("lf");
    static const SBuf withToken("with");

    auto currentToken = parser.token("command");
    Must(currentToken.cmp("replace") == 0);
    command_ = Command::replace;
        
    currentToken = parser.token("command argument");
    commandArgument_ = CommandArguments.at(SBuf(currentToken));

    auto flags = REG_EXTENDED | REG_NEWLINE;
    auto reExpr = reNs;
    currentToken = parser.delimitedToken(reExpr, "regular expression");
    if (reExpr.length()) {
        if (reExpr[0] != '(' && reExpr[reExpr.length() - 1] != ')')
            throw TextException(ToSBuf("missing flags parenthesis"), Here());
        SBuf rawFlags = reExpr.substr(1, reExpr.length() - 2);
        for (const auto f: rawFlags) {
            if (f == 'i')
                flags |= REG_ICASE;
            else if (f == 's')
                flags &= ~REG_NEWLINE;
            else if (f == 'm')
                flags |= REG_NEWLINE;
            // TODO: parse other flags
        }
    }

    compileRE(currentToken, flags);

    if (patterns_.empty())
        throw TextException("missing regular expression(s)", Here());

    currentToken = parser.token("'with' keyword");
    if (currentToken != withToken)
        throw TextException(ToSBuf("missing 'with' keyword"), Here());

    auto lfEpr = lfNs;
    formatString_ = parser.delimitedToken(lfEpr, "replacement expression");
    if (lfEpr.length())
        throw TextException("the replacement expression does not expect flags", Here());

    assert(!format_);
    format_ = new Format::Format("malformed header editor");

    if (!format_->parse(UnescapeXXX(formatString_)/*formatString_.c_str()*/)) {
         delete format_;
         throw TextException(ToSBuf("invalid format line: ", formatString_), Here());
    }
    aclList = parser.optionalAclList();
}

void
Http::HeaderEditor::dump(std::ostream &os) const
{
    os << "command: replace";
    os << " command argument: " << CommandArgumentString(commandArgument_) << "\n";
    // TODO: dump flags
    os << " regex patterns: \n";
    for (const auto &p: patterns_)
        os << p.c_str() << "\n";
    os << " format: " << formatString_ << "\n";
    if (aclList) {
        for (const auto &acl: aclList->treeDump("if", &Acl::AllowOrDeny))
            os << ' ' << acl;
    }
}

namespace Configuration {

template <>
Http::HeaderEditor *
Configuration::Component<Http::HeaderEditor*>::Parse(ConfigParser &parser)
{
    return new Http::HeaderEditor(parser);
}

template <>
void
Configuration::Component<Http::HeaderEditor*>::Print(std::ostream &os, Http::HeaderEditor* const &editor)
{
    assert(editor);
    editor->dump(os);
}

template <>
void
Configuration::Component<Http::HeaderEditor*>::Free(Http::HeaderEditor * const editor)
{
    delete editor;
}

} // namespace Configuration

