/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_PROTOCOLDATA_H
#define SQUID_SRC_ACL_PROTOCOLDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "anyp/ProtocolType.h"

#include <list>

class ACLProtocolData : public ACLData<AnyP::ProtocolType>
{
    MEMPROXY_CLASS(ACLProtocolData);

public:
    ACLProtocolData() {}
    ~ACLProtocolData() override;
    bool match(AnyP::ProtocolType) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override {return values.empty();}

    std::list<AnyP::ProtocolType> values;
};

#endif /* SQUID_SRC_ACL_PROTOCOLDATA_H */

