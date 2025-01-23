/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "acl/Tree.h"
#include "base/TextException.h"
#include "cache_cf.h"
#include "ConfigOption.h"
#include "format/Format.h"
#include "parser/Tokenizer.h"
#include "proxyp/OutgoingHttpConfig.h"
#include "sbuf/Stream.h"

ProxyProtocol::Option::Option(const char *aName): theName(aName),valueFormat(nullptr)
{}

ProxyProtocol::Option::Option(const char *aName, const char *aVal, bool quoted)
    : theName(aName), theValue(aVal), valueFormat(nullptr)
{
    if (quoted)
        parse();
}

void
ProxyProtocol::Option::parse()
{
    valueFormat = new Format::Format(theName.c_str());
    if (!valueFormat->parse(theValue.c_str())) {
        delete valueFormat;
        throw TextException(ToSBuf("failed to parse value ", theValue), Here());
    }
}

const SBuf &
ProxyProtocol::Option::format(const AccessLogEntryPointer &al)
{
    if (al && valueFormat) {
        static MemBuf mb;
        mb.reset();
        valueFormat->assemble(mb, al, 0);
        theFormattedValue.assign(mb.content());
        return theFormattedValue;
    }
    return theValue;
}

ProxyProtocol::OutgoingHttpConfig::OutgoingHttpConfig(ConfigParser &parser)
{
    parseOptions(parser);
    aclList = parser.optionalAclList();
}

void
ProxyProtocol::OutgoingHttpConfig::dump(std::ostream &os)
{
    if (aclList) {
        // TODO: Use Acl::dump() after fixing the XXX in dump_acl_list().
        for (const auto &acl: ToTree(aclList).treeDump("if", &Acl::AllowOrDeny))
            os << ' ' << acl;
    }
}

Ip::Address
ProxyProtocol::OutgoingHttpConfig::getAddr(const AccessLogEntryPointer &al, const size_t addrIdx, const size_t portIdx) const
{
    auto formattedAddr = params[addrIdx]->format(al);
    Ip::Address addr;
    if (auto optAddr =  Ip::Address::Parse(formattedAddr.c_str())) {
        addr = *optAddr;
    } else {
        debugs(3, DBG_IMPORTANT, "WARNING: cannot parse " << params[addrIdx]->theName << ", using default");
    }

    auto formattedPort = params[portIdx]->format(al);
    Parser::Tokenizer tok(formattedPort);
    int64_t port = -1;
    if (!tok.int64(port, 10, false) || (port > std::numeric_limits<uint16_t>::max())) {
        debugs(3, DBG_IMPORTANT, "WARNING: cannot parse " << params[portIdx]->theName << ", using default");
        port = 0;
    }
    addr.port(port);

    return addr;
}

void
ProxyProtocol::OutgoingHttpConfig::parseOptions(ConfigParser &)
{
    // required options
    params.push_back(new Option("src_addr"));
    params.push_back(new Option("dst_addr"));
    params.push_back(new Option("src_port"));
    params.push_back(new Option("dst_port"));

    char *key = nullptr;
    char *value = nullptr;
    for (auto &p : params)  {
        if(!ConfigParser::NextKvPair(key, value))
            throw TextException(ToSBuf("missing ", p->theName, " option"), Here());
        if (p->theName.cmp(key) != 0)
            throw TextException(ToSBuf("expecting ", p->theName, ", but found ", key, " option"), Here());
        p->theValue = value;
        p->parse();
    }

    // optional tlvs
    while (ConfigParser::NextKvPair(key, value)) {
        const auto it =  std::find_if(params.begin(), params.end(), [&](const Option::Pointer &p) {
                return p->theName == SBuf(key) && p->theValue == SBuf(value);
        });
        if (it != params.end()) {
            throw TextException(ToSBuf("duplicate option: ", key, "=", value), Here());
        }
        params.push_back(new Option(key, value, ConfigParser::LastTokenWasQuoted()));
    }
}

namespace Configuration {

template <>
ProxyProtocol::OutgoingHttpConfig *
Configuration::Component<ProxyProtocol::OutgoingHttpConfig*>::Parse(ConfigParser &parser)
{
    return new ProxyProtocol::OutgoingHttpConfig(parser);
}

template <>
void
Configuration::Component<ProxyProtocol::OutgoingHttpConfig*>::Print(std::ostream &os, ProxyProtocol::OutgoingHttpConfig* const & cfg)
{
    assert(cfg);
    cfg->dump(os);
}

template <>
void
Configuration::Component<ProxyProtocol::OutgoingHttpConfig*>::Free(ProxyProtocol::OutgoingHttpConfig * const cfg)
{
    delete cfg;
}

} // namespace Configuration

