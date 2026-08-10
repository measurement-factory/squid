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

int
Acl::ClientAlpn::match(ACLChecklist * const ch)
{
    //TODO implement
    const auto checklist = Filled(ch);
    assert(checklist != nullptr && checklist->request != nullptr);

    if (ConnStateData *conn = checklist->conn()) {
        Security::TlsDetails::Pointer const &details = conn->tlsParser.details;
        conn->clientConnection->tlsNegotiations()->retrieveParsedInfo(details);
        if (details && !details->tlsAppLayerProtoNeg.isEmpty()) {
            debugs(28, 5, "Client ALPN: " << details->tlsAppLayerProtoNeg);
        }
    }
    return 0;
}

