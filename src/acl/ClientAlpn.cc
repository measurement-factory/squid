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
#include "client_side.h"
#include "parser/BinaryTokenizer.h"
#include "security/Handshake.h"
#include "security/NegotiationHistory.h"

int
Acl::ClientAlpn::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);
    assert(checklist != nullptr && checklist->request != nullptr);

    if (ConnStateData *conn = checklist->conn()) {
        Security::TlsDetails::Pointer const &details = conn->tlsParser.details;
        conn->clientConnection->tlsNegotiations()->retrieveParsedInfo(details);
        if (details && !details->tlsAppLayerProtoNeg.isEmpty()) {
            // tlsAppLayerProtoNeg is a raw RFC 7301 ProtocolNameList: a sequence
            // of 1-byte-length-prefixed protocol names, not a single string
            Parser::BinaryTokenizer tk(details->tlsAppLayerProtoNeg);
            while (!tk.atEnd()) {
                const auto protocol = tk.pstring8("ALPN protocol");
                debugs(28, 5, "checking ALPN protocol '" << protocol << "'");
                if (data->match(protocol.c_str()))
                    return 1;
            }
        }
    }
    return 0;
}

