/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Options.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "sbuf/Stream.h"

#include <iostream>
#include <vector>

namespace Acl {

/// low-level parser that extracts but does not interpret ACL options
class OptionExtractor
{
public:
    /// parses the next option and fills public members with its details
    /// \returns whether option extraction was successful
    bool extractOne();

    /* extracted option details (after successful extraction */
    SBuf name; ///< extracted option name, including dash(es)
    bool hasValue = false; ///< whether the option has a value (-x=value)
    const SBuf &value() const; ///< extracted option value (requires hasValue)
    /// depending on the option name prefix, whether the option is set ('-', '--') or unset ('+')
    bool isSet() const { return (prefix_[0] == '-'); }

protected:
    bool advance();
    void extractWhole();
    void extractShort();

private:
    SBuf prefix_; ///< option name(s), including leading dash(es)
    SBuf value_; ///< the last seen value of some option
    SBuf::size_type letterPos_ = 0; ///< letter position inside an -xyz sequence
    bool sawValue_ = false; ///< the current option sequence had a value
};

/// parses/validates/stores ACL options; skips/preserves parameter flags
class OptionsParser
{
public:
    OptionsParser(const Options &options);

    // fill previously supplied options container, throwing on errors
    void parse();

private:
    const Option *findOption(/* const */ SBuf &rawName);
    /// ACL parameter flags in parsing order
    typedef std::vector<OptionName> Names;

    const Options &options_; ///< caller-supported, linked options
};

} // namespace Acl

/* Acl::OptionNameCmp */

bool
Acl::OptionNameCmp::operator()(const OptionName a, const OptionName b) const
{
    return strcmp(a, b) < 0;
}

/* Acl::OptionExtractor */

const SBuf &
Acl::OptionExtractor::value() const
{
    Must(hasValue);
    return value_;
}

bool
Acl::OptionExtractor::extractOne()
{
    if (!prefix_.isEmpty()) {
        extractShort(); // continue with the previously extracted flags
        return true;
    }

    if (!advance())
        return false; // end of options (and, possibly, the whole "acl" directive)

    if (prefix_.length() < 2)
        throw TexcHere(ToSBuf("truncated(?) ACL flag: ", prefix_)); // single - or +

    if (prefix_[0] == '-' && prefix_[1] == '-') {
        if (prefix_.length() == 2)
            return false; // skipped "--", an explicit end-of-options marker
        extractWhole();
        return true;
    }

    if (prefix_.length() == 2) { // common trivial case: -x or +y
        extractWhole();
        return true;
    }

    // -xyz or +xyz
    letterPos_ = 1;
    extractShort();
    return true;
}

/// extracts a token with the next option/flag(s) or returns false
bool
Acl::OptionExtractor::advance()
{
    const char *next = ConfigParser::PeekAtToken();
    if (!next)
        return false; // end of the "acl" line

    const char nextChar = *next;
    if (!(nextChar == '-' || nextChar == '+'))
        return false; // start of ACL parameters

    sawValue_ = strchr(next, '='); // TODO: Make ConfigParser reject '^=.*' tokens
    if (sawValue_) {
        char *rawPrefix = nullptr;
        char *rawValue = nullptr;
        if (!ConfigParser::NextKvPair(rawPrefix, rawValue))
            throw TexcHere(ToSBuf("Malformed acl option=value: ", next));
        prefix_.assign(rawPrefix);
        value_.assign(rawValue);
    } else {
        prefix_.assign(next);
        ConfigParser::NextToken(); // consume what we have peeked at
    }
    return true;
}

/// handles -x[=option] or --foo[=option]
void
Acl::OptionExtractor::extractWhole()
{
    debugs(28, 8, "from " << prefix_ << " value: " << sawValue_);
    hasValue = sawValue_;
    name = prefix_;
    prefix_.clear();
}

/// handles one flag letter inside an -xyx[=option] or +xyz[=option] sequence
void
Acl::OptionExtractor::extractShort()
{
    debugs(28, 8, "from " << prefix_ << " at " << letterPos_ << " value: " << sawValue_);
    name.assign(prefix_.rawContent(), 1); // leading - or +
    name.append(prefix_.at(letterPos_++));
    if (letterPos_ >= prefix_.length()) { // got last flag in the sequence
        hasValue = sawValue_;
        prefix_.clear();
    } else {
        hasValue = false;
    }
}

/* Acl::OptionsParser */

Acl::OptionsParser::OptionsParser(const Options &options):
    options_(options)
{
}

const Acl::Option *
Acl::OptionsParser::findOption(/* const */ SBuf &rawNameBuf)
{
    // TODO: new std::map::find() in C++14 does not require this conversion
    const auto rawName = rawNameBuf.c_str();

    const auto optionPos = options_.find(rawName);
    if (optionPos != options_.end())
        return optionPos->second;

    throw TexcHere(ToSBuf("unsupported ACL option: ", rawNameBuf));
}

void
Acl::OptionsParser::parse()
{
    OptionExtractor oex;
    while (oex.extractOne()) {
        /* const */ auto rawName = oex.name;
        if (const Option *optionPtr = findOption(rawName)) {
            const Option &option = *optionPtr;
            if (option.configured())
                debugs(28, 7, "acl uses multiple " << rawName << " options");
            switch (option.valueExpectation)
            {
            case Option::valueNone:
                if (oex.hasValue)
                    throw TexcHere(ToSBuf("unexpected value for an ACL option: ", rawName, '=', oex.value()));
                option.configureFlag(oex.isSet());
                break;
            case Option::valueRequired:
                if (!oex.hasValue)
                    throw TexcHere(ToSBuf("missing required value for ACL option ", rawName));
                option.configureWith(oex.value());
                break;
            case Option::valueOptional:
                if (oex.hasValue)
                    option.configureWith(oex.value());
                else
                    option.configureFlag(oex.isSet());
                break;
            }
        }
        // else skip supported parameter flag
    }
}


const Acl::Options &
Acl::CaseLineOptions::options()
{
    static const Acl::BooleanOption CaseInsensitiveOn;
    static const Acl::BooleanOption CaseInsensitiveOff;
    static const Acl::Options MyOptions = { { "-i", &CaseInsensitiveOn }, { "+i", &CaseInsensitiveOff } };
    CaseInsensitiveOn.linkWith(&caseInsensitive);
    CaseInsensitiveOff.linkWith(&caseInsensitive);
    return MyOptions;
}

void
Acl::ParseFlags(const Options &options)
{
    OptionsParser parser(options);
    parser.parse();
}

const Acl::Options &
Acl::NoOptions()
{
    static const Options none;
    return none;
}

std::ostream &
operator <<(std::ostream &os, const Acl::Option &option)
{
    if (option.valued()) {
        os << '=';
        option.print(os);
    }
    return os;
}

std::ostream &
operator <<(std::ostream &os, const Acl::Options &options)
{
    for (const auto pos: options) {
        assert(pos.second);
        const auto &option = *pos.second;
        if (option.configured())
            os << pos.first << option;
    }
    // TODO: Remember "--" presence and print that delimiter when present.
    // Detecting its need is difficult because parameter flags start with "-".
    return os;
}

