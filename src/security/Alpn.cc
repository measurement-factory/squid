/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS session management */

#include "squid.h"
#include "base/Assure.h"
#include "base/TextException.h"
#include "globals.h"
#include "parser/BinaryTokenizer.h"
#include "sbuf/SBuf.h"
#include "security/Alpn.h"
#include "security/Session.h"

#if USE_OPENSSL
static int
ClientAlpnObservationCallback(SSL *ssl, const unsigned char **, unsigned char *, const unsigned char *in, unsigned int inlen, void *)
{
    if (const auto old = static_cast<const SBuf *>(SSL_get_ex_data(ssl, ssl_ex_index_client_alpn)))
        delete old;
    SSL_set_ex_data(ssl, ssl_ex_index_client_alpn, new SBuf(reinterpret_cast<const char *>(in), inlen));
    return SSL_TLSEXT_ERR_NOACK;
}
#endif /* USE_OPENSSL */

void
Security::EnableClientAlpnObservation(ContextPointer &ctx)
{
#if USE_OPENSSL
    Assure(ctx);
    SSL_CTX_set_alpn_select_cb(ctx.get(), ClientAlpnObservationCallback, nullptr);
#else
    (void)ctx;
#endif /* USE_OPENSSL */
}

Security::AlpnProtocols
Security::ParseAlpnList(const SBuf &rawList)
{
    AlpnProtocols protocols;
    try {
        Parser::BinaryTokenizer tk(rawList);
        while (!tk.atEnd())
            protocols.emplace_back(tk.pstring8("ALPN"));
    } catch (...) {
        debugs(83, 3, "malformed offered ALPN protocol list: " << CurrentException);
        return AlpnProtocols();
    }
    return protocols;
}

Security::AlpnProtocols
Security::ObservedClientAlpns(const SessionPointer &session)
{
#if USE_OPENSSL
    if (session) {
        if (const auto rawList = static_cast<const SBuf *>(SSL_get_ex_data(session.get(), ssl_ex_index_client_alpn)))
            return ParseAlpnList(*rawList);
    }
#else
    (void)session;
#endif /* USE_OPENSSL */
    return AlpnProtocols();
}

