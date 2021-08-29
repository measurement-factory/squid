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
#include "base/RegexPattern.h"
#include "ConfigOption.h"
#include "format/Format.h"
#include "http/HeaderEditor.h"
#include "MemBuf.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

#include <map>

static const int ReGroupMax = 10;

typedef std::map<SBuf, Http::HeaderEditor::Command> CommandMap;
static const CommandMap Commands =
{
    {SBuf("replace"), Http::HeaderEditor::Command::replace}
};

typedef std::map<SBuf, Http::HeaderEditor::CommandArgument> CommandArgumentMap;
static const CommandArgumentMap CommandArguments =
{
    {SBuf("first"), Http::HeaderEditor::CommandArgument::first},
    {SBuf("all"), Http::HeaderEditor::CommandArgument::all},
    {SBuf("each"), Http::HeaderEditor::CommandArgument::each}
};

static SBuf
CommandString(const Http::HeaderEditor::Command command)
{
    for (const auto p: Commands) {
        if (p.second == command)
            return p.first;
    }
    return SBuf();
}

static SBuf
CommandArgumentString(const Http::HeaderEditor::CommandArgument commandArgument)
{
    for (const auto p: CommandArguments) {
        if (p.second == commandArgument)
            return p.first;
    }
    return SBuf();
}
    
Http::HeaderEditor::HeaderEditor(ConfigParser &parser, const char *desc):
    description_(desc)
{
    parseOptions(parser);
}

Http::HeaderEditor::~HeaderEditor()
{
    aclDestroyAclList(&aclList);
    delete format_;
}

bool
Http::HeaderEditor::compileRE(SBuf &str, const int flags)
{
    // TODO: removeUnnecessaryWildcards()
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
Http::HeaderEditor::fix(const SBuf &input, const AccessLogEntryPointer &al)
{
    al_ = al;
    auto output = input;
    for (auto &pattern : patterns_) {
        if (pattern.match(output.c_str(), ReGroupMax)) {
            switch (commandArgument_) {
            case CommandArgument::first:
                applyOne(output, pattern);
                break;
            case CommandArgument::all:
                applyAll(output, pattern);
                break;
            case CommandArgument::each:
                applyEach(output, pattern);
                break;
             }
        }
    }
    return output;
}

void
Http::HeaderEditor::applyEach(SBuf &input, RegexPattern &pattern)
{
    auto s = input.c_str();
    SBuf result;
    while (s && pattern.match(s, ReGroupMax)) {
        static MemBuf mb;
        mb.reset();
        matchedCount_++;
        result.append(s, pattern.startOffset());
        format_->assemble(mb, al_, 0, &pattern);
        result.append(mb.content(), mb.contentSize());
        s += pattern.endOffset();
    }
    result.append(s);
    input = result;
}

void
Http::HeaderEditor::applyAll(SBuf &input, RegexPattern &pattern)
{
    auto s = input.c_str();
    SBuf result;

    while (s && pattern.match(s, ReGroupMax)) {
        matchedCount_++;
        result.append(s, pattern.startOffset());
        if (matchedCount_ == 1) {
            static MemBuf mb;
            mb.reset();
            format_->assemble(mb, al_, 0, &pattern);
            result.append(mb.content(), mb.contentSize());
        }
        s += pattern.endOffset();
    }
    result.append(s);
    input = result;
}

void
Http::HeaderEditor::applyOne(SBuf &input, RegexPattern &pattern)
{
    auto s = input.c_str();
    SBuf result;

    if (s && pattern.match(s, ReGroupMax)) {
        static MemBuf mb;
        mb.reset();
        matchedCount_++;
        result.append(s, pattern.startOffset());
        format_->assemble(mb, al_, 0, &pattern);
        result.append(s, pattern.startOffset());
    }
    result.append(s);
    input = result;
}

uint64_t
Http::HeaderEditor::ParseReGroupId(const char *str)
{
    auto tok = Parser::Tokenizer(SBuf(str));
    int64_t id = 0;
    if (!tok.int64(id, 10, false))
        throw TexcHere("malformed regex group ID");
    return static_cast<uint64_t>(id);
}

void
Http::HeaderEditor::parseOptions(ConfigParser &parser)
{
    static const SBuf reNs("re");
    static const SBuf lfNs("lf");
    static const SBuf withToken("with");

    auto currentToken = parser.token("command");
    // the only command for now
    Must(currentToken.cmp("replace") == 0);
    command_ = Command::replace;
        
    currentToken = parser.token("command argument");
    commandArgument_ = CommandArguments.at(SBuf(currentToken));

    auto flags = REG_EXTENDED | REG_NEWLINE;
    auto reExpr = reNs;
    currentToken = parser.delimitedToken(reExpr, "regular expression");
    if (reExpr.length()) {
        if (reExpr[0] != '(' && reExpr[reExpr.length() - 1] != ')')
            throw TextException(ToSBuf("missing flags brackets"), Here());
        SBuf rawFlags = reExpr.substr(1, reExpr.length() - 1);
        for (auto f: rawFlags) {
            if (f == 'i')
              flags |= REG_ICASE;
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
    format_ = new Format::Format(description_);
    if (!format_->parse(currentToken.c_str())) {
        delete format_;
        throw TextException(ToSBuf("invalid format line:", formatString_), Here());
    }

    aclList = parser.optionalAclList();
}

void
Http::HeaderEditor::dump(std::ostream &os) const
{
    os << "command: " << CommandString(command_);
    os << " command argument: " << CommandArgumentString(commandArgument_) << "\n";
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
    return new Http::HeaderEditor(parser, "malformed_reply_header_edit");
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

