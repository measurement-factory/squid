/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_ARGUMENTPARSER_H
#define SQUID_ACL_ARGUMENTPARSER_H

#include "acl/forward.h"
#include "sbuf/forward.h"


class ConfigParser;

namespace Acl {

class ArgumentParser
{
public:
    ArgumentParser(ConfigParser &aParser, ACL &anAcl)
        : parser(aParser), acl(anAcl) {}

    /// Extracts and returns the next ACL argument, that is not an ACL option.
    /// If the current acl directive has no more arguments, returns nil.
    char * optionalValue();

    /// optionalValue() that also supports ACL line options (may be provided
    /// in-between ACL values)
    /// \see ACL::lineOptions()
    char * optionalValueOrMiddleOption();

    /// optionalValueOrMiddleOption() for an ACL that expects regex arguments
    char * optionalRegexValueOrMiddleOption();

    /// Extract, validate, and store the ACL key parameter for ACL types
    /// declared using "acl aclname type key argument..." declaration that
    /// require unique key values for each aclname+type combination.
    /// Key comparison is case-insensitive.
    void setAclKey(SBuf &keyStorage, const char *keyParameterName);

private:

    /// verifies that token is not a flag and returns it
    char *asValue(char *token);

    /// Extracts and returns the next ACL argument (or nil)
    char *optionalAclToken();

    /// whether token either a two-character short option starting with '-'
    /// or a multi-character long option, starting with "--"
    bool isOption(const char *token) const;

    /// whether token is a 'global' option, supported by acl
    bool isAclOption(const char *taken, const Acl::Options &options) const;

    ConfigParser &parser;
    ACL &acl;
};

} // namespace Acl

#endif  /* SQUID_ACL_ARGUMENTPARSER_H */

