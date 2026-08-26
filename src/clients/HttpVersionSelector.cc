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
#include "ConfigOption.h"
#include "ConfigParser.h"
#include "configuration/Smooth.h"
#include "HttpVersionSelector.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"


static bool
parseProtocol(const SBuf &protocol)
{
    if (protocol == ClientHttpVersionSelector::Http11Protocol)
        return true;
    else if (protocol.cmp("h2") == 0)
        return true;
    else if (protocol == ClientHttpVersionSelector::AnyProtocol)
        return true;
    return false;
}

ClientHttpVersion::ClientHttpVersion(ConfigParser &parser)
{
    const auto version = parser.token("client http version type");
    if (!parseProtocol(version))
        throw TextException(ToSBuf("unsupported client http version: '", version, "'"), Here());
    protocol = version;
    aclList = parser.optionalAclList();
}

ClientHttpVersion::~ClientHttpVersion()
{
    aclDestroyAclList(&aclList);
}

void
ClientHttpVersion::print(std::ostream &os) const
{
    os << protocol << '\n';
}

static std::optional<SBuf>
Supported(const char *clientProtocol, const unsigned int protoLen)
{
    const auto &supportedProtocol = ClientHttpVersionSelector::Http11Protocol;
    return supportedProtocol.cmp(clientProtocol, protoLen) == 0 ? std::make_optional(supportedProtocol) : std::nullopt;
}

static bool
Matched(const SBuf &candidateProtocol, const char *clientProto, unsigned int clientProtoLen)
{
    return candidateProtocol.cmp(clientProto, clientProtoLen) == 0 || candidateProtocol.cmp("any") == 0;
}

static std::optional<SBuf>
CheckProtocol(const char *in, unsigned int inLen, const SBuf &matchedProtocol)
{
    if (!in) {
        assert(!inLen);
        // A client not providing ALPN usually intends to use http/1.1.
        const auto &clientDefault = ClientHttpVersionSelector::Http11Protocol;
        if (Matched(matchedProtocol, clientDefault.rawContent(), clientDefault.length()))
            return clientDefault;
        return std::nullopt;
    }

    assert(inLen);

    auto current = in;
    auto remaining = inLen;
    while (remaining > 0) {
        unsigned int protoLen = *current;
        assert(remaining > protoLen);
        auto clientProtocol = current+1;
        if (Matched(matchedProtocol, clientProtocol, protoLen))
            return Supported(clientProtocol, protoLen);

        // the buffer boundaries must have been checked by tls_parse_ctos_alpn()
        current += (protoLen + 1);
        remaining -= (protoLen + 1);
    }

    return std::nullopt;
}

void
ClientHttpVersionSelector::add(ConfigParser &parser)
{
    directives.emplace_back(std::make_shared<ClientHttpVersion>(parser));
}

const std::optional<SBuf>
ClientHttpVersionSelector::Check(ACLFilledChecklist *ch, const char *alpn, unsigned int alpnLen)
{
    if (!ch)
        return CheckProtocol(alpn, alpnLen, ClientHttpVersionSelector::AnyProtocol);

    assert(Config.clientHttpVersionSelector);
    return Config.clientHttpVersionSelector->check(alpn ,alpnLen, *ch);
}

const std::optional<SBuf>
ClientHttpVersionSelector::check(const char *alpn, unsigned int alpnLen, ACLFilledChecklist &ch)
{
    auto matchedVersion = std::find_if(directives.begin(), directives.end(), [&](const ClientHttpVersion::Pointer& version) {
        return !version->aclList || ch.fastCheck(version->aclList).allowed();
    });

    const auto proto = (matchedVersion == directives.end()) ?  AnyProtocol : (*matchedVersion)->protocol;
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
    if (!Config.clientHttpVersionSelector && sr.fresh.clientHttpVersionSelector->directives.empty())
        return;

    Reset(Config.clientHttpVersionSelector);

    if (sr.fresh.clientHttpVersionSelector->directives.size())
        Config.clientHttpVersionSelector = new ClientHttpVersionSelector(*sr.fresh.clientHttpVersionSelector);
 }

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::Reconfigure(SmoothReconfiguration &sr, ClientHttpVersionSelector *&, ConfigParser &parser)
{
    sr.fresh.clientHttpVersionSelector->add(parser);
}

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::Parse(ClientHttpVersionSelector *&raw, ConfigParser &parser)
{
    if (!raw)
        raw = new ClientHttpVersionSelector();
    raw->add(parser);
}

template <>
void
Configuration::Component<ClientHttpVersionSelector*>::Print(std::ostream &os, ClientHttpVersionSelector * const &selector, const char * const directiveName)
{
    Assure(selector);

    for (const auto &version: selector->directives) {
        os << directiveName << ' ';
        version->print(os);
    }
}
