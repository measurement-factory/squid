/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ATSTEPDATA_H
#define SQUID_SRC_ACL_ATSTEPDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "XactionStep.h"
#include <list>

class ACLAtStepData : public ACLData<XactionStep>
{
    MEMPROXY_CLASS(ACLAtStepData);

public:
    ACLAtStepData();
    ~ACLAtStepData() override;
    bool match(XactionStep) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

    std::list<XactionStep> values;
};

#endif /* SQUID_SRC_ACL_ATSTEPDATA_H */

