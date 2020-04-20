/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREGEXDATA_H
#define SQUID_ACLREGEXDATA_H

#include "acl/Data.h"

#include <list>

class RegexPattern;

class ACLRegexData : public ACLData<char const *>
{
    MEMPROXY_CLASS(ACLRegexData);

public:
    virtual ~ACLRegexData();
    bool match(char const *user) override;
    SBufList dump() const override;
    void parse() override;
    const Acl::ParameterFlags &supportedFlags() const override;
    bool empty() const override;
    ACLData<char const *> *clone() const override;

private:
    std::list<RegexPattern> data;
};

#endif /* SQUID_ACLREGEXDATA_H */

