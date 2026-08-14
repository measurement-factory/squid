/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/ClientAlpn.h"
#include "acl/FilledChecklist.h"
#include "security/Handshake.h"
#include "security/NegotiationHistory.h"
#include "client_side.h"
#include "base/TextException.h"
#include "ConfigParser.h"

SBufList ACLClientAlpnData::dump() const
{
    SBufList sl;
    sl.push_back(preferredAlpn);
    if (!otherAlpn.isEmpty())
        sl.push_back(otherAlpn);
    return sl;
}

void ACLClientAlpnData::parse()
{
    const char *t = ConfigParser::strtokFile();
    if (!t)
        throw TextException("tls::client_alpn requires a protocol name", Here());
    preferredAlpn = SBuf(t);

    if (const char *t2 = ConfigParser::strtokFile())
        otherAlpn = SBuf(t2);
}

bool ACLClientAlpnData::empty() const
{
    return preferredAlpn.isEmpty();
}

bool ACLClientAlpnData::match(char const *)
{
    return false;
}

int
Acl::ClientAlpn::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);
    assert(checklist != nullptr && checklist->request != nullptr);

    if (ConnStateData *conn = checklist->conn()) {
        Security::TlsDetails::Pointer const &details = conn->tlsParser.details;
        conn->clientConnection->tlsNegotiations()->retrieveParsedInfo(details);
        if (details && !details->tlsAppLayerProtoNeg.isEmpty()) {
            debugs(28, 5, "Client ALPN: " << details->tlsAppLayerProtoNeg);
            return data->match(details->tlsAppLayerProtoNeg);
        }
    }
    return 0;
}

