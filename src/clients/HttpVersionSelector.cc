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

static ClientHttpVersion::Protocol
parseProtocol(const SBuf &protocol)
{
    if (protocol.cmp("http/1.1") == 0)
        return ClientHttpVersion::http11;
    else if (protocol.cmp("h2") == 0)
        return ClientHttpVersion::h2;
    else if (protocol.cmp("any") == 0)
        return ClientHttpVersion::any;
    else
        return ClientHttpVersion::none;
}

ClientHttpVersion::ClientHttpVersion(ConfigParser &parser)
{
    const auto version = parser.token("client http version type");
    protocol = parseProtocol(version);
    if (protocol == none)
        throw TextException(ToSBuf("unsupported client http version: '", version, "'"), Here());
    aclList = parser.optionalAclList();
}

ClientHttpVersion::~ClientHttpVersion()
{
    aclDestroyAclList(&aclList);
}

void
ClientHttpVersion::print(std::ostream &os) const
{
    switch (protocol) {
    case none:
        os << "none";
        break;
    case http11:
        os << "http/1.1";
        break;
    case h2:
        os << "h2";
        break;
    case any:
        os << "any";
        break;
    }
    os << "\n";
}

void
ClientHttpVersionSelector::add(ConfigParser &parser)
{
    directives.emplace_back(std::make_shared<ClientHttpVersion>(parser));
}

bool
ClientHttpVersionSelector::check(const SBufList &protocols, ACLFilledChecklist &ch)
{
    std::vector<ClientHttpVersion::Protocol> clientProtocols;
    for (auto p: protocols) {
        const auto parsed = parseProtocol(p);
        if (parsed != ClientHttpVersion::none)
            clientProtocols.push_back(parsed);
    }

    for (auto &version: directives) {
        if (!version->aclList || ch.fastCheck(version->aclList).allowed()) {
            for (auto p: clientProtocols)
                return (p == version->protocol || version->protocol == ClientHttpVersion::any);
        }
    }
    return true;
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
