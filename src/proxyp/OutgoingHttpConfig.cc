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
#include "parser/Tokenizer.h"
#include "proxyp/Header.h"
#include "proxyp/OutgoingHttpConfig.h"
#include "sbuf/Stream.h"

ProxyProtocol::Option::Option(const char *aName, const char *aVal, bool quoted)
    : theName(aName), theValue(aVal), valueFormat(nullptr)
{
    if (quoted)
        parseFormat();
}

void
ProxyProtocol::Option::parseFormat()
{
    valueFormat = new Format::Format(theName.c_str());
    if (!valueFormat->parse(theValue.c_str())) {
        delete valueFormat;
        throw TextException(ToSBuf("failed to parse value ", theValue), Here());
    }
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

static std::optional<Ip::Address>
ParseAddr(const SBuf &val)
{
    const auto addr = Ip::Address::Parse(SBuf(val).c_str());
    if (!addr)
        throw TextException(ToSBuf("Cannot parse '", val, "' as an IP address"), Here());
    return addr;
}

ProxyProtocol::AddrOption::AddrOption(const char *aName, const char *aVal, bool quoted) : Option(aName, aVal, quoted)
{
    if (!valueFormat || !valueFormat->hasPercentCode())
        address_ = ParseAddr(theValue);
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
        return ParseAddr(formattedValue);
    } catch (...) {
        return FormatFailure(theName);
    }
}

static unsigned short
ParsePort(const SBuf &val)
{
    Parser::Tokenizer tok(val);
    int64_t p = -1;
    if (!tok.int64(p, 10, false) || (p > std::numeric_limits<uint16_t>::max()))
        throw TextException(ToSBuf("Cannot parse '", val, "' as an IP port"), Here());
    return p;
}

ProxyProtocol::PortOption::PortOption(const char *aName, const char *aVal, bool quoted) : Option(aName, aVal, quoted)
{
    if (!valueFormat || !valueFormat->hasPercentCode())
        port_ = ParsePort(theValue);
}

ProxyProtocol::PortOption::Port
ProxyProtocol::PortOption::port(const AccessLogEntryPointer &al) const
{
    if(port_)
        return *port_;
    try
    {
        const auto formattedValue = processFormat(al);
        return ParsePort(formattedValue);
    } catch (...) {
        return FormatFailure(theName);
    }
}

ProxyProtocol::TlvOption::TlvOption(const char *aName, const char *aVal, bool quoted) : Option(aName, aVal, quoted)
{
    const uint8_t typeMin = 0xe0;
    const uint8_t typeMax = 0xef;

    int64_t t = -1;
    Parser::Tokenizer tok(theName);
    if (!tok.int64(t, 0, false) || (t < typeMin || t > typeMax))
        throw TextException(ToSBuf("expected tlv type as a decimal or hex number in the [0xE0, 0xEF] range but got ", theName), Here());
    tlvType_ = static_cast<uint8_t>(t);

    if (!valueFormat || !valueFormat->hasPercentCode())
        tlvValue_ = theValue;
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
    if (aclList) {
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
    auto p = srcPort->port(al);
    src.port(p ? *p : 0);
    p = dstPort->port(al);
    dst.port(p ? *p : 0);
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

    // source and destination are non-empty
    if (!src->isAnyAddr() && !dst->isAnyAddr()) {
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        throw TextException(ToSBuf("Address family mismatch: ", srcAddr->theName, "(", *src, ") and ", dstAddr->theName, "(", *dst, ")"), Here());
    }

    // source and/or destination are empty
    if (!src->isAnyAddr()) {
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
    } else if (!dst->isAnyAddr()) {
        adjustedSrc = dst->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        adjustedDst = *dst;
    } else { // if source and destination are empty, keep the source family and adjust destination
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
    }
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
    srcAddr = new AddrOption("src_addr", requiredValue("src_addr"), ConfigParser::LastTokenWasQuoted());
    dstAddr = new AddrOption("dst_addr", requiredValue("dst_addr"), ConfigParser::LastTokenWasQuoted());
    srcPort = new PortOption("src_addr", requiredValue("src_port"), ConfigParser::LastTokenWasQuoted());
    dstPort = new PortOption("dst_addr", requiredValue("dst_port"), ConfigParser::LastTokenWasQuoted());

    if (srcAddr->hasAddress() && dstAddr->hasAddress()) {
        Ip::Address adjustedSrc, adjustedDst;
        adjustAddresses(adjustedSrc, adjustedDst, AccessLogEntryPointer());
        srcAddr->setAddress(adjustedSrc);
        dstAddr->setAddress(adjustedDst);
    }

    char *key = nullptr;
    char *value = nullptr;

    // optional tlvs
    while (parser.optionalKvPair(key, value)) {
        const auto it =  std::find_if(tlvOptions.begin(), tlvOptions.end(), [&](const TlvOption::Pointer &p) {
            return p->theName == SBuf(key) && p->theValue == SBuf(value);
        });
        if (it != tlvOptions.end()) {
            throw TextException(ToSBuf("duplicate option: ", key, "=", value), Here());
        }
        tlvOptions.push_back(new TlvOption(key, value, ConfigParser::LastTokenWasQuoted()));
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

