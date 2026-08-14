/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_CLIENTALPN_H
#define SQUID_SRC_ACL_CLIENTALPN_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"

class ACLClientAlpnData: public ACLData<char const *>
{
    MEMPROXY_CLASS(ACLClientAlpnData);
public:
    ACLClientAlpnData() {}
    ~ACLClientAlpnData() override {}
    /// \deprecated use match(SBuf&) instead.
    bool match(char const *) override;
    bool match(const SBuf &);
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;
private:
    SBuf preferredAlpn;
    SBuf otherAlpn;
};

namespace Acl
{

/// an "tls::client_alpn" ACL
class ClientAlpn : public ParameterizedNode<ACLClientAlpnData>
{
public:
    /* Acl::Node API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_CLIENTALPN_H */

