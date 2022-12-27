/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "acl/Acl.h"
#include "acl/ArgumentParser.h"
#include "acl/Options.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Messages.h"
#include "sbuf/Stream.h"

/// whether token either a two-character short option starting with '-'
/// or a multi-character long option, starting with "--"
static bool
IsOption(const char *name)
{
    assert(name);
    return name[0] == '-' && (strlen(name) == 2 || (strlen(name) > 2 && name[1] == '-'));
}

/// whether token is a 'global' option, supported by acl
static bool
IsAclOption(const char *name, const Acl::Options &options)
{
    assert(name);
    for (const auto opt: options) {
        if (opt->onName && strcmp(name, opt->onName) == 0)
            return true;
        if (opt->offName && strcmp(name, opt->offName) == 0)
            return true;
    }
    return false;
}

char *
Acl::ArgumentParser::optionalValueOrMiddleOption()
{
    if (auto token = optionalAclToken()) {
        if (IsAclOption(token, acl.lineOptions())) {
            if (!ConfigParser::PeekAtToken())
                debugs(28, DBG_IMPORTANT, "WARNING: suspicious ACL line option " << token << " at the end of the line");
            return token;
        }
        return asValue(token);
    }
    return nullptr;
}

char *
Acl::ArgumentParser::optionalValue()
{
    Assure(acl.lineOptions() == Acl::NoOptions());
    if (auto token = optionalAclToken())
        return asValue(token);
    return nullptr;
}

char *
Acl::ArgumentParser::asValue(char *token)
{
    if (IsAclOption(token, acl.options()))
        throw TextException(ToSBuf("the ACL option ", token, " must be placed before other non-option arguments"), Here());
    else if (IsOption(token))
        debugs(28, Important(66), "WARNING: suspicious option-like ACL argument " << token);
    return token;
}

char *
Acl::ArgumentParser::optionalAclToken()
{
    if (ConfigParser::RecognizeQuotedValues)
        return ConfigParser::NextToken();

    static int fromFile = 0;
    static FILE *wordFile = nullptr;

    char *t;
    static char buf[CONFIG_LINE_LIMIT];

    do {

        if (!fromFile) {
            ConfigParser::TokenType tokenType;
            t = ConfigParser::NextElement(tokenType);
            if (!t) {
                return nullptr;
            } else if (*t == '\"' || *t == '\'') {
                /* quote found, start reading from file */
                debugs(3, 8,"Quoted token found : " << t);
                char *fn = ++t;

                while (*t && *t != '\"' && *t != '\'')
                    ++t;

                *t = '\0';

                if ((wordFile = fopen(fn, "r")) == nullptr) {
                    debugs(3, DBG_CRITICAL, "ERROR: Can not open file " << fn << " for reading");
                    return nullptr;
                }

#if _SQUID_WINDOWS_
                setmode(fileno(wordFile), O_TEXT);
#endif

                fromFile = 1;
            } else {
                return t;
            }
        }

        /* fromFile */
        if (fgets(buf, sizeof(buf), wordFile) == nullptr) {
            /* stop reading from file */
            fclose(wordFile);
            wordFile = nullptr;
            fromFile = 0;
            return nullptr;
        } else {
            char *t2, *t3;
            t = buf;
            /* skip leading and trailing white space */
            t += strspn(buf, w_space);
            t2 = t + strcspn(t, w_space);
            t3 = t2 + strspn(t2, w_space);

            while (*t3 && *t3 != '#') {
                t2 = t3 + strcspn(t3, w_space);
                t3 = t2 + strspn(t2, w_space);
            }

            *t2 = '\0';
        }

        /* skip comments */
        /* skip blank lines */
    } while ( *t == '#' || !*t );

    return t;
}

char *
Acl::ArgumentParser::optionalRegexValueOrMiddleOption()
{
    if (ConfigParser::RecognizeQuotedValues) {
        debugs(3, DBG_CRITICAL, "FATAL: Can not read regex expression while configuration_includes_quoted_values is enabled");
        self_destruct();
    }
    ConfigParser::RecognizeQuotedPair_ = true;
    auto token = optionalValueOrMiddleOption();
    ConfigParser::RecognizeQuotedPair_ = false;
    return token;
}

void
Acl::ArgumentParser::setAclKey(SBuf &keyStorage, const char *keyParameterName)
{
    const auto newKey = optionalValue();
    if (!newKey) {
        throw TextException(ToSBuf("An acl declaration is missing a ", keyParameterName,
                                   Debug::Extra, "ACL name: ", AclMatchedName),
                            Here());
    }

    if (keyStorage.isEmpty()) {
        keyStorage = newKey;
        return;
    }

    if (keyStorage.caseCmp(newKey) == 0)
        return; // no change

    throw TextException(ToSBuf("Attempt to change the value of the ", keyParameterName, " argument in a subsequent acl declaration:",
                               Debug::Extra, "previously seen value: ", keyStorage,
                               Debug::Extra, "new/conflicting value: ", newKey,
                               Debug::Extra, "ACL name: ", AclMatchedName,
                               Debug::Extra, "advice: Use a dedicated ACL name for each distinct ", keyParameterName,
                               " (and group those ACLs together using an 'any-of' ACL)."),
                        Here());
}

