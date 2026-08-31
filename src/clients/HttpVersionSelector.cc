/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "acl/Tree.h"
#include "base/Raw.h"
#include "ConfigOption.h"
#include "ConfigParser.h"
#include "configuration/Smooth.h"
#include "HttpVersionSelector.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"

#include <algorithm>
#include <array>
#include <utility>

static const std::array<std::pair<ClientHttpVersionSelector::Protocol, const char *>, 3> ProtoVersionMap = {{
    {ClientHttpVersionSelector::http11, "http/1.1" },
    {ClientHttpVersionSelector::h2, "h2"},
    {ClientHttpVersionSelector::any, "any"}
}};

const SBuf ClientHttpVersionSelector::Http11Protocol(ProtoVersionMap[ClientHttpVersionSelector::http11].second);
const SBuf ClientHttpVersionSelector::Http2Protocol(ProtoVersionMap[ClientHttpVersionSelector::h2].second);
const SBuf ClientHttpVersionSelector::AnyProtocol(ProtoVersionMap[ClientHttpVersionSelector::any].second);

static std::optional<ClientHttpVersionSelector::Protocol>
parseProtocol(const SBuf &protocol)
{
    auto it = std::find_if(ProtoVersionMap.begin(), ProtoVersionMap.end(), [&](const auto &p) {
            return protocol.cmp(p.second) == 0;
            });
    if (it == ProtoVersionMap.end())
        return std::nullopt;
    return it->first;
}

static std::optional<SBuf>
ClientSupported(const char *clientProtocol, const unsigned int protoLen)
{
    const auto &supportedProtocol = ClientHttpVersionSelector::Http11Protocol;
    return supportedProtocol.cmp(clientProtocol, protoLen) == 0 ? std::make_optional(supportedProtocol) : std::nullopt;
}

static bool
ConfigurationSupported(const SBuf &candidateProtocol)
{
    return candidateProtocol == ClientHttpVersionSelector::Http11Protocol || candidateProtocol == ClientHttpVersionSelector::AnyProtocol;
}

static bool
ClientMatched(const SBuf &candidateProtocol, const char *clientProto, unsigned int clientProtoLen)
{
    return candidateProtocol.cmp(clientProto, clientProtoLen) == 0 || candidateProtocol.cmp("any") == 0;
}

static std::optional<SBuf>
CheckProtocol(const char *in, unsigned int inLen, const SBuf &matchedProtocol)
{
    debugs(11, 5, "Configuration candidate: " << matchedProtocol << " has ALPN: " << bool(in));

    if (!ConfigurationSupported(matchedProtocol))
        return std::nullopt;

    if (!in) {
        assert(!inLen);
        // A client not providing ALPN usually intends to use http/1.1.
        return (matchedProtocol == ClientHttpVersionSelector::AnyProtocol) ? ClientHttpVersionSelector::Http11Protocol : matchedProtocol;
    }

    assert(inLen);

    auto current = in;
    auto remaining = inLen;
    while (remaining > 0) {
        unsigned int protoLen = *current;
        Assure(remaining > protoLen);
        auto clientProtocol = current+1;
        debugs(11, 5, Raw("ALPN candidate", clientProtocol, protoLen));
        if (ClientMatched(matchedProtocol, clientProtocol, protoLen)) {
            if (auto resultProtocol = ClientSupported(clientProtocol, protoLen)) {
                debugs(11, 2, "Selected HTTP version: " << *resultProtocol);
                return resultProtocol;
            }
        }
        // the buffer boundaries must have been checked by the OpenSSL library (tls_parse_ctos_alpn() or equivalent)
        current += (protoLen + 1);
        remaining -= (protoLen + 1);
    }

    debugs(11, 2, "Selected none");
    return std::nullopt;
}

void
ClientHttpVersionSelector::parse(ConfigParser &parser)
{
    const auto version = parser.token("client http version type");

    auto proto = parseProtocol(version);
    if (!proto)
        throw TextException(ToSBuf("unsupported client http version: '", version, "'"), Here());

    auto action = Acl::Answer(ACCESS_ALLOWED);
    action.kind = *proto;

    auto raw = aclList.get();
    ParseOptionalAclWithAction(parser, &raw, action, "client_http_version");
    if (!aclList)
        aclList.reset(raw);
}

const std::optional<SBuf>
ClientHttpVersionSelector::Check(ACLFilledChecklist *ch, const char *alpn, unsigned int alpnLen)
{
    if (!ch)
        return CheckProtocol(alpn, alpnLen, ClientHttpVersionSelector::AnyProtocol);

    Assure(Config.clientHttpVersionSelector);
    auto aclList =  Config.clientHttpVersionSelector->aclList.get();
    Assure(aclList);

    const auto &answer = ch->fastCheck(aclList);
    auto proto = AnyProtocol;
    if (answer.allowed()) {
        auto it = std::find_if(ProtoVersionMap.begin(), ProtoVersionMap.end(), [&](const auto &p) {
            return answer.kind == p.first;
        });
        Assure(it != ProtoVersionMap.end());
        proto = it->second;
    }

    return CheckProtocol(alpn, alpnLen, proto);
}

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::Reset(ClientHttpVersionSelector *&selector)
{
    delete selector;
    selector = nullptr;
}

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::StartSmoothReconfiguration(SmoothReconfiguration &)
{
}

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::FinishSmoothReconfiguration(SmoothReconfiguration &sr)
{
    if (!Config.clientHttpVersionSelector && !sr.fresh.clientHttpVersionSelector->aclList)
        return;

    Reset(Config.clientHttpVersionSelector);

    // if parsed at least one directive
    if (sr.fresh.clientHttpVersionSelector->aclList)
        Config.clientHttpVersionSelector = new ClientHttpVersionSelector(std::move(*sr.fresh.clientHttpVersionSelector));
 }

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::Reconfigure(SmoothReconfiguration &sr, ClientHttpVersionSelector *&, ConfigParser &parser)
{
    sr.fresh.clientHttpVersionSelector->parse(parser);
}

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::Parse(ClientHttpVersionSelector *&raw, ConfigParser &parser)
{
    if (!raw)
        raw = new ClientHttpVersionSelector();

    raw->parse(parser);
}

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::Print(std::ostream &os, ClientHttpVersionSelector * const &selector, const char * const directiveName)
{
    Assure(selector);

    if (auto list = selector->aclList.get()) {
        const auto lines = ToTree(list).treeDump(directiveName, [](const Acl::Answer &action) {
            auto it = std::find_if(ProtoVersionMap.begin(), ProtoVersionMap.end(), [&](const auto &p) {
                    return p.first == action.kind;
            });
            assert(it == ProtoVersionMap.end());
            return it->second;
        });
        for (const auto &line : lines)
            os << line << " ";
        os << "\n";
    }
}

