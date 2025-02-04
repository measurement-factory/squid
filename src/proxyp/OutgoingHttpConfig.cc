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
#include "base/IoManip.h"
#include "base/TextException.h"
#include "cache_cf.h"
#include "ConfigOption.h"
#include "ConfigParser.h"
#include "format/Format.h"
#include "format/Token.h"
#include "parser/Tokenizer.h"
#include "proxyp/Header.h"
#include "proxyp/OutgoingHttpConfig.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"

ProxyProtocol::Option::Option(const char *aName, ConfigParser &parser)
    : theName(aName), theQuoted(parser.LastTokenWasQuoted()), valueFormat(nullptr)
{
    char *key = nullptr;
    char *value = nullptr;
    if(!parser.optionalKvPair(key, value))
        throw TextException(ToSBuf("missing ", theName, " option"), Here());
    if (theName.cmp(key) != 0)
        throw TextException(ToSBuf("expected ", theName, ", but got ", key, " option"), Here());
    parseFormat(value);
}

ProxyProtocol::Option::Option(const char *aName, const char *aValue, bool quoted)
    : theName(aName), theQuoted(quoted), valueFormat(nullptr)
{
    parseFormat(aValue);
}

ProxyProtocol::Option::~Option()
{
    delete valueFormat;
}

std::ostream &
ProxyProtocol::operator << (std::ostream &os, const Option &opt)
{
    os << opt.theName << '=';
    SBufStream valueOs;
    opt.valueFormat->format->print(valueOs);
    const auto buf = valueOs.buf();
    if (opt.theQuoted)
        os << ConfigParser::QuoteString(SBufToString(buf));
    else
        os << buf;
    return os;
}

void
ProxyProtocol::Option::parseFormat(const char *value)
{
    Assure(!valueFormat);
    auto format = std::unique_ptr<Format::Format>(new Format::Format(theName.c_str()));
    if (!format->parse(value)) {
        throw TextException(ToSBuf("failed to parse value ", value), Here());
    }
    valueFormat = format.release();
}

SBuf
ProxyProtocol::Option::processFormat(const AccessLogEntryPointer &al) const
{
    Assure(valueFormat);
    static MemBuf mb;
    mb.reset();
    valueFormat->assemble(mb, al, 0);
    return SBuf(mb.content());
}

std::optional<Ip::Address>
ProxyProtocol::AddrOption::parseAddr(const SBuf &val) const
{
    const auto addr = Ip::Address::Parse(SBuf(val).c_str());
    if (!addr)
        throw TextException(ToSBuf("Cannot parse '", val, "' as ", theName), Here());
    return addr;
}

ProxyProtocol::AddrOption::AddrOption(const char *aName, ConfigParser &parser) : Option(aName, parser)
{
    if (!valueFormat->hasPercentCode()) {
        const auto formattedValue = processFormat(AccessLogEntryPointer());
        address_ = parseAddr(formattedValue);
    }
}

static std::nullopt_t
FormatFailure(const SBuf &what)
{
    debugs(17, DBG_IMPORTANT, "WARNING: could not process logformat for " << what <<
           Debug::Extra << "problem: " << CurrentException);
    return std::nullopt;
}

ProxyProtocol::AddrOption::Addr
ProxyProtocol::AddrOption::address(const AccessLogEntryPointer &al) const
{
    if(address_)
        return address_;
    try
    {
        const auto formattedValue = processFormat(al);
        return parseAddr(formattedValue);
    } catch (...) {
        return FormatFailure(theName);
    }
}

uint16_t
ProxyProtocol::PortOption::parsePort(const SBuf &val) const
{
    Parser::Tokenizer tok(val);
    int64_t p = -1;
    if (!tok.int64(p, 10, false) || p > std::numeric_limits<uint16_t>::max())
        throw TextException(ToSBuf("Cannot parse '", p, "' as ", theName, ". Expect an unsigned less than ", std::numeric_limits<uint16_t>::max()), Here());
    return p;
}

ProxyProtocol::PortOption::PortOption(const char *aName, ConfigParser &parser) : Option(aName, parser)
{
    if (!valueFormat->hasPercentCode()) {
        const auto formattedValue = processFormat(AccessLogEntryPointer());
        port_ = parsePort(formattedValue);
    }
}

ProxyProtocol::PortOption::Port
ProxyProtocol::PortOption::port(const AccessLogEntryPointer &al) const
{
    if(port_)
        return *port_;
    try
    {
        const auto formattedValue = processFormat(al);
        return parsePort(formattedValue);
    } catch (...) {
        return FormatFailure(theName);
    }
}

ProxyProtocol::TlvOption::TlvOption(const char *aName, const char *aValue, const bool quoted) : Option(aName, aValue, quoted)
{
    const uint8_t typeMin = 0xe0;
    const uint8_t typeMax = 0xef;

    int64_t t = -1;
    Parser::Tokenizer tok(theName);
    if (!tok.int64(t, 0, false) || (t < typeMin || t > typeMax))
        throw TextException(ToSBuf("Expected tlv type as a decimal or hex number in the [0xE0, 0xEF] range but got ", theName), Here());
    tlvType_ = static_cast<uint8_t>(t);

    if (!valueFormat->hasPercentCode())
        tlvValue_ = processFormat(AccessLogEntryPointer());
}

ProxyProtocol::TlvOption::TlvValue
ProxyProtocol::TlvOption::tlvValue(const AccessLogEntryPointer &al) const
{
    if(tlvValue_)
        return *tlvValue_;
    try
    {
        return TlvValue(processFormat(al));
    } catch (...) {
        return FormatFailure(theName);
    }
}

ProxyProtocol::OutgoingHttpConfig::OutgoingHttpConfig(ConfigParser &parser)
{
    parseOptions(parser);
    aclList = parser.optionalAclList();
}

void
ProxyProtocol::OutgoingHttpConfig::dump(std::ostream &os)
{
    const auto separator = " ";
    os << *srcAddr << separator << *dstAddr << separator << srcPort << separator << dstPort <<
        AsList(tlvOptions).prefixedBy(separator).delimitedBy(separator);
    if (aclList) {
        os << separator;
        // TODO: Use Acl::dump() after fixing the XXX in dump_acl_list().
        for (const auto &acl: ToTree(aclList).treeDump("if", &Acl::AllowOrDeny))
            os << ' ' << acl;
    }
}

void
ProxyProtocol::OutgoingHttpConfig::fill(ProxyProtocol::Header &header, const AccessLogEntryPointer &al)
{
    fillAddresses(header.sourceAddress, header.destinationAddress, al);
    fillTlvs(header.tlvs, al);
}

void
ProxyProtocol::OutgoingHttpConfig::fillAddresses(Ip::Address &src, Ip::Address &dst, const AccessLogEntryPointer &al)
{
    try {
        adjustAddresses(src,dst, al);
    } catch (...)
    {
        debugs(17, DBG_IMPORTANT, "WARNING: could not parse or match addresses, enforcing defaults." <<
               Debug::Extra << "problem: " << CurrentException);
    }
    src.port(srcPort->port(al).value_or(0));
    dst.port(dstPort->port(al).value_or(0));
}

void
ProxyProtocol::OutgoingHttpConfig::fillTlvs(Tlvs &tlvs, const AccessLogEntryPointer &al) const
{
    for (auto &t : tlvOptions) {
        auto v = t->tlvValue(al);
        tlvs.emplace_back(t->tlvType(), v ? *v : SBuf(""));
    }
}

void
ProxyProtocol::OutgoingHttpConfig::adjustAddresses(Ip::Address &adjustedSrc, Ip::Address &adjustedDst, const AccessLogEntryPointer &al)
{
    auto src = srcAddr->address(al);
    auto dst = dstAddr->address(al);

    // source and/or destination are missing
    if (!src && !dst) {
        // IPv4 by default
        adjustedSrc = Ip::Address::AnyAddrIPv4();
        adjustedDst = Ip::Address::AnyAddrIPv4();
        return;
    } else if (!src) {
        adjustedSrc = dst->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        adjustedDst = *dst;
        return;
    } else if (!dst) {
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        return;
    }

    // source and destination have the same address family
    if (src->isIPv4() == dst->isIPv4()) {
        adjustedSrc = *src;
        adjustedDst = *dst;
        return;
    }

    // source and destination have different address family

    if (!src->isAnyAddr() && !dst->isAnyAddr()) {
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
    } else {
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
    }

    throw TextException(ToSBuf("Address family mismatch: ", srcAddr->theName, "(", *src, ") and ", dstAddr->theName, "(", *dst, ")"), Here());
}

const char *
ProxyProtocol::OutgoingHttpConfig::requiredValue(const char *name)
{
    char *key = nullptr;
    char *value = nullptr;
    if(!ConfigParser::NextKvPair(key, value))
        throw TextException(ToSBuf("missing ", name, " option"), Here());
    if (strcmp(name, key) != 0)
        throw TextException(ToSBuf("expected ", name, ", but got ", key, " option"), Here());
    return value;
}

void
ProxyProtocol::OutgoingHttpConfig::parseOptions(ConfigParser &parser)
{
    // required options
    srcAddr = new AddrOption("src_addr", parser);
    dstAddr = new AddrOption("dst_addr", parser);
    srcPort = new PortOption("src_port", parser);
    dstPort = new PortOption("dst_port", parser);

    if (srcAddr->hasAddress() && dstAddr->hasAddress()) {
        Ip::Address adjustedSrc, adjustedDst;
        adjustAddresses(adjustedSrc, adjustedDst, AccessLogEntryPointer());
        srcAddr->setAddress(adjustedSrc);
        dstAddr->setAddress(adjustedDst);
    }

    char *key = nullptr;
    char *value = nullptr;

    // optional TLVs
    std::vector< std::pair<SBuf, SBuf> > parsedTlvs;
    while (parser.optionalKvPair(key, value)) {
        const auto it =  std::find_if(parsedTlvs.begin(), parsedTlvs.end(), [&](const auto &p) {
            return p.first == SBuf(key) && p.second == SBuf(value);
        });
        if (it != parsedTlvs.end()) {
            throw TextException(ToSBuf("duplicate TLV option: ", key, "=", value), Here());
        }
        parsedTlvs.emplace_back(key, value);
        tlvOptions.push_back(new TlvOption(key, value, parser.LastTokenWasQuoted()));
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

