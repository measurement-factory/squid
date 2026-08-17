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
    if (protocol.cmp("http/1.1") == 0)
        return true;
    else if (protocol.cmp("h2") == 0)
        return true;
    else if (protocol.cmp("any") == 0)
        return true;
    return false;
}

ClientHttpVersion::ClientHttpVersion(ConfigParser &parser)
{
    const auto version = parser.token("client http version type");
    if (parseProtocol(version))
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

void
ClientHttpVersionSelector::add(ConfigParser &parser)
{
    directives.emplace_back(std::make_shared<ClientHttpVersion>(parser));
}

bool
ClientHttpVersionSelector::supported(const char *proto, const unsigned int protoLen) const {
    return strncmp(proto, "http/1.1", protoLen) == 0;
}

std::optional<std::string_view>
ClientHttpVersionSelector::check(ACLFilledChecklist &ch)
{
    return check(nullptr, 0, ch);
}

std::optional<std::string_view>
ClientHttpVersionSelector::check(const char *in, unsigned int inLen, ACLFilledChecklist &ch)
{
    static const char http11_alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    if (!in) {
        in = &http11_alpn[1];
        inLen = http11_alpn[0];
    }

    for (auto &version: directives) {
        if (!version->aclList || ch.fastCheck(version->aclList).allowed()) {
            // 'in' contains the client's offered ALPN protocols in format:
            // [len][string][len][string]... (e.g., \x02h2\x08http/1.1)
            auto current = in;
            auto remaining = inLen;
            while (remaining > 0) {
                unsigned int protoLen = *current;
                const char *proto = current+1;
                if ((version->protocol.cmp(proto, protoLen) == 0 || version->protocol.cmp("any") == 0) && supported(proto, protoLen)) {
                    return std::make_optional<std::string_view>(current, protoLen+1);
                }
                current += (protoLen + 1);
                remaining -= (protoLen + 1);
            }
            return std::string_view{};
        }
    }
    return std::nullopt;
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
