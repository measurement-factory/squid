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
#include "base/TextException.h"
#include "ConfigParser.h"
#include "sbuf/Stream.h"

#include <set>

bool ACLClientAlpnData::isSupportedAlpn(const SBuf &alpn) {
    static const std::set<SBuf> supportedAlpns = {
        SBuf("h2"),
        SBuf("http/1.1")
    };
    return supportedAlpns.find(alpn) != supportedAlpns.end();
}

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
    const auto t = ConfigParser::strtokFile();
    if (!t)
        throw TextException("tls::client_alpn requires a protocol name", Here());
    preferredAlpn = SBuf(t);

    if (!isSupportedAlpn(preferredAlpn))
        throw TextException(ToSBuf("tls::client_alpn uses ", preferredAlpn, " which is unsupported"), Here());

    if (const auto t2 = ConfigParser::strtokFile())
        otherAlpn = SBuf(t2);

    if (!otherAlpn.isEmpty()) {
        if (preferredAlpn == otherAlpn)
            throw TextException(ToSBuf("tls::client_alpn uses duplicate protocol: ", preferredAlpn), Here());

        if (!isSupportedAlpn(otherAlpn))
            throw TextException(ToSBuf("tls::client_alpn uses ", otherAlpn, " which is unsupported"), Here());

        if (ConfigParser::strtokFile())
            throw TextException("tls::client_alpn only supports one optional alternative protocol", Here());
    }
}

bool ACLClientAlpnData::empty() const
{
    return preferredAlpn.isEmpty();
}

bool ACLClientAlpnData::match(const Security::AlpnProtocols &protocols)
{
    for (const auto &alpn: protocols) {
        if (alpn == preferredAlpn)
            return true;
        if (!otherAlpn.isEmpty() && alpn == otherAlpn)
            return false;
    }

    return false;
}

int
Acl::ClientAlpn::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);
    assert(checklist);

    if (!checklist->al || checklist->al->ssl.clientAlpns.empty()) {
        debugs(28, 3, "ALPN list offered by the client is empty");
        return 0;
    }

    return data->match(checklist->al->ssl.clientAlpns);
}

