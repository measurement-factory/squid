/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSTRATEGISED_H
#define SQUID_ACLSTRATEGISED_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/Strategy.h"

// XXX: Replace with a much simpler abstract ACL child class without the
// ACLStrategy parameter (and associated call forwarding). Duplicating key
// portions of the ACL class API in ACLStrategy is not needed because
// ACLStrategy is unused outside the ACLStrategised context. Existing classes
// like ACLExtUser, ACLProxyAuth, and ACLIdent seem to confirm this assertion.
// It also requires forwarding ACL info to ACLStrategy as method parameters.

/// Splits the ACL API into two individually configurable components:
/// * ACLStrategy that usually extracts information from the current transaction
/// * ACLData that usually matches information against admin-configured values
template <class M>
class ACLStrategised : public ACL
{
    MEMPROXY_CLASS(ACLStrategised);

public:
    typedef M MatchType;

    ~ACLStrategised();
    ACLStrategised(ACLData<MatchType> *, ACLStrategy<MatchType> *, char const *);
    ACLStrategised(ACLStrategised const &&) = delete;

    char const *typeString() const override;
    void parseFlags() override;

    bool requiresRequest() const override {return matcher->requiresRequest();}

    bool requiresReply() const override {return matcher->requiresReply();}

    void prepareForUse() override { data->prepareForUse();}
    const Acl::Options &options() override { return matcher->options(); }
    void parse() override;
    int match(ACLChecklist *checklist) override;
    virtual int match (M const &);
    SBufList dump() const override;
    bool empty () const override;
    bool valid () const override;

private:
    ACLData<MatchType> *data;
    char const *type_;
    ACLStrategy<MatchType> *matcher;
};

/* implementation follows */

template <class MatchType>
ACLStrategised<MatchType>::~ACLStrategised()
{
    delete data;
}

template <class MatchType>
ACLStrategised<MatchType>::ACLStrategised(ACLData<MatchType> *newData, ACLStrategy<MatchType> *theStrategy, char const *theType): data(newData), type_(theType), matcher(theStrategy)
{}

template <class MatchType>
char const *
ACLStrategised<MatchType>::typeString() const
{
    return type_;
}

template <class MatchType>
void
ACLStrategised<MatchType>::parseFlags()
{
    ParseFlags(options(), data->supportedFlags());
}

template <class MatchType>
void
ACLStrategised<MatchType>::parse()
{
    data->parse();
}

template <class MatchType>
bool
ACLStrategised<MatchType>::empty() const
{
    return data->empty();
}

template <class MatchType>
int
ACLStrategised<MatchType>::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = dynamic_cast<ACLFilledChecklist*>(cl);
    assert(checklist);
    return matcher->match(data, checklist);
}

template <class MatchType>
int
ACLStrategised<MatchType>::match(MatchType const &toFind)
{
    return data->match(toFind);
}

template <class MatchType>
SBufList
ACLStrategised<MatchType>::dump() const
{
    return data->dump();
}

template <class MatchType>
bool
ACLStrategised<MatchType>::valid () const
{
    return matcher->valid();
}

#endif /* SQUID_ACLSTRATEGISED_H */

