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

    void prohibitOption(const char *) const;

    /// Extracts and returns the next ACL argument, that is not a ACL option.
    /// If the current acl directive has no more arguments, returns nil.
    char * strtokFile();

    /// strtokFile() for an ACL that expects regex arguments
    char * regexStrtokFile();

    /// Extract, validate, and store the ACL key parameter for ACL types
    /// declared using "acl aclname type key argument..." declaration that
    /// require unique key values for each aclname+type combination.
    /// Key comparison is case-insensitive.
    void setAclKey(SBuf &keyStorage, const char *keyParameterName);

private:

    /// Extracts and returns the next ACL argument.
    /// If the current acl directive has no more arguments, returns nil.
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

