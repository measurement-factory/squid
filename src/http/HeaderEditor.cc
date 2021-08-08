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

Http::HeaderEditor::Action
Http::HeaderEditor::fix(const char **fieldStart, const char **fieldEnd)
{
    assert(fieldStart && *fieldStart);
    assert(fieldEnd && *fieldEnd);

    if (matchedCount_ && commandArgument_ == CommandArgument::first)
        return Action::ignore;

    SBuf input(*fieldStart, *fieldEnd - *fieldStart);
    for (auto &pattern : patterns_) {
        if (pattern.match(input.c_str(), ReGroupMax)) {
            matchedCount_++;
            static MemBuf mb;
            mb.reset();
            // XXX: pass ALE here
            format_->assemble(mb, AccessLogEntryPointer(), 0, &pattern);
            *fieldStart = mb.content();
            *fieldEnd = mb.space();
            switch (commandArgument_) {
                case CommandArgument::first:
                    assert(matchedCount_ == 1);
                    return Action::apply;
                case CommandArgument::all:
                    return (matchedCount_ == 1) ? Action::apply : Action::remove;
                case CommandArgument::each:
                    return Action::apply;
            }
        }
    }
    return Action::ignore;
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
    auto currentToken = parser.token("command");

    Must(currentToken.cmp("replace") == 0);
    command_ = Command::replace;
        
    currentToken = parser.token("command argument");
    commandArgument_ = CommandArguments.at(SBuf(currentToken));

    // TODO: add lf::"FORMAT" support to allow multiline format specifications with comments
    static const SBuf rePrefix("re::");
    static const SBuf lfPrefix("lf::");
    static const SBuf withToken("with");

    while (const auto t = ConfigParser::NextToken()) {
    	const SBuf token(t);
        Parser::Tokenizer tok(token);
        if (!tok.skip(rePrefix)) {
            Must(tok.remaining() == withToken);
            break;
        }
        auto flags = REG_EXTENDED;
        const auto rawFlags = tok.prefix("flags", CharacterSet::ALPHA);
        for (auto f: rawFlags) {
            if (f == 'i')
                flags |= REG_ICASE;
            // TODO: parse other flags
        }
        Must(tok.skip('"'));
        auto regEx = tok.prefix("regex", CharacterSet::DQUOTE.complement("non-dquote"));
        compileRE(regEx, flags);
    }

    if (patterns_.empty())
        throw TextException("missing regular expression(s)", Here());

    currentToken = parser.token("replacement expression");

    Parser::Tokenizer tok(currentToken);
    Must(!tok.skip(lfPrefix));
    Must(tok.skip('"'));
    formatString_ = tok.prefix("format string", CharacterSet::DQUOTE.complement("non-dquote"));

    assert(!format_);
    format_ = new Format::Format(description_);
    if (!format_->parse(formatString_.c_str())) {
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

