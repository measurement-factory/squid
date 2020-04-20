/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_EXTUSER_H
#define SQUID_EXTUSER_H

#if USE_AUTH

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"

class ACLExtUser : public ACL
{
    MEMPROXY_CLASS(ACLExtUser);

public:
    ACLExtUser(ACLData<char const *> *newData, char const *);
    ACLExtUser (ACLExtUser const &old);
    ACLExtUser & operator= (ACLExtUser const &rhs);
    ~ACLExtUser();

    /* ACL API */
    char const *typeString() const override;
    void parse() override;
    void parseFlags() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty () const override;
    virtual ACL *clone()const;

private:
    ACLData<char const *> *data;
    char const *type_;
};

#endif /* USE_AUTH */
#endif /* SQUID_EXTUSER_H */

