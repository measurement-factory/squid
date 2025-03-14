/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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
#include "parser/Tokenizer.h"
#include "proxyp/Header.h"
#include "proxyp/OutgoingHttpConfig.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"

ProxyProtocol::Option::Option(const char * const name, const char * const logformat):
    value_(nullptr)
{
    parseLogformat(name, logformat);
}

ProxyProtocol::Option::~Option()
{
    delete value_;
}

const char *
ProxyProtocol::Option::name() const
{
    Assure(value_);
    Assure(value_->name);
    return value_->name;
}

void
ProxyProtocol::Option::dump(std::ostream &os) const
{
    Assure(value_);
    os << name() << '=';
    // for simplicity sake, we always quote the value
    //
    // XXX: If an admin did not use quotes but did use escape sequences valid
    // inside quoted values (see ConfigParser::UnQuote()), then we may be
    // misrepresenting actual configuration by quoting the value. TODO: Require
    // quotes!
    os << '"';
    value_->dumpDefinition(os);
    os << '"';
}

/// parses named logformat specification
void
ProxyProtocol::Option::parseLogformat(const char * const name, const char * const logformat)
{
    Assure(!value_);
    auto format = std::unique_ptr<Format::Format>(new Format::Format(name));
    if (!format->parse(logformat)) {
        throw TextException(ToSBuf("failed to parse logformat specs: ", logformat), Here());
    }
    value_ = format.release();
}

std::nullopt_t
ProxyProtocol::Option::valueAssemblingFailure() const
{
    debugs(17, DBG_IMPORTANT, "WARNING: Failed to compute the value of http_outgoing_proxy_protocol " << name() << " parameter" <<
           Debug::Extra << "problem: " << CurrentException);
    return std::nullopt;
}

SBuf
ProxyProtocol::Option::assembleValue(const AccessLogEntryPointer &al) const
{
    Assure(value_);
    static MemBuf mb;
    mb.reset();
    value_->assemble(mb, al, 0);
    return SBuf(mb.content());
}

ProxyProtocol::AddrOption::AddrOption(const char * const aName, const char * const logformatSpecs) : Option(aName, logformatSpecs)
{
    Assure(value_);
    if (!value_->isConstant()) {
        const auto formattedValue = assembleValue(AccessLogEntryPointer());
        address_ = parseAddr(formattedValue);
    }
}

ProxyProtocol::AddrOption::Addr
ProxyProtocol::AddrOption::parseAddr(const SBuf &val) const
{
    if (val == Format::Dash)
        return std::nullopt;

    const auto addr = Ip::Address::Parse(SBuf(val).c_str());
    if (!addr)
        throw TextException(ToSBuf("Cannot parse '", val, "' as ", name()), Here());
    return addr;
}

ProxyProtocol::AddrOption::Addr
ProxyProtocol::AddrOption::address(const AccessLogEntryPointer &al) const
{
    if(address_)
        return address_;
    try
    {
        const auto formattedValue = assembleValue(al);
        return parseAddr(formattedValue);
    } catch (...) {
        return valueAssemblingFailure();
    }
}

ProxyProtocol::PortOption::PortOption(const char * const aName, const char * const logformatSpecs) : Option(aName, logformatSpecs)
{
    Assure(value_);
    if (!value_->isConstant()) {
        const auto formattedValue = assembleValue(AccessLogEntryPointer());
        port_ = parsePort(formattedValue);
    }
}

ProxyProtocol::PortOption::Port
ProxyProtocol::PortOption::parsePort(const SBuf &val) const
{
    if (val == Format::Dash)
        return std::nullopt;

    Parser::Tokenizer tok(val);
    const auto portMax = std::numeric_limits<uint16_t>::max();
    int64_t p = -1;
    if (!tok.int64(p, 10, false) || !tok.atEnd() || p > portMax)
        throw TextException(ToSBuf("Cannot parse '", val, "' as ", name(), ". Expected an unsigned integer not exceeding ", portMax), Here());
    return p;
}

ProxyProtocol::PortOption::Port
ProxyProtocol::PortOption::port(const AccessLogEntryPointer &al) const
{
    if(port_)
        return *port_;
    try
    {
        const auto formattedValue = assembleValue(al);
        return parsePort(formattedValue);
    } catch (...) {
        return valueAssemblingFailure();
    }
}

ProxyProtocol::TlvOption::TlvOption(const char *aName, const char *aValue):
    Option(aName, aValue)
{
    const TlvType typeMin = 0xe0;
    const TlvType typeMax = 0xef;

    int64_t t = -1;
    auto tok = Parser::Tokenizer(SBuf(name())); // TODO: Convert Format::Format::name to SBuf
    if (!tok.int64(t, 0, false) || (t < typeMin || t > typeMax))
        throw TextException(ToSBuf("Expected tlv type as a decimal or hex number in the [0xE0, 0xEF] range but got ", name()), Here());
    tlvType_ = static_cast<TlvType>(t);

    Assure(value_);
    if (!value_->isConstant())
        tlvValue_ = assembleValue(AccessLogEntryPointer());
}

ProxyProtocol::TlvOption::TlvValue
ProxyProtocol::TlvOption::tlvValue(const AccessLogEntryPointer &al) const
{
    if(tlvValue_)
        return *tlvValue_;
    try
    {
        const auto formatted = assembleValue(al);
        const auto max = std::numeric_limits<uint16_t>::max();
        if (formatted.length() > max)
            throw TextException(ToSBuf("Expected tlv value size less than ", max, " but got ", formatted.length(), " bytes"), Here());
        return TlvValue(assembleValue(al));
    } catch (...) {
        return valueAssemblingFailure();
    }
}

namespace ProxyProtocol
{
/// XXX: Document
template <class T>
static T
MakeRequiredOption(const char * const name, ConfigParser &parser)
{
    char *key = nullptr;
    char *value = nullptr;
    if(!parser.optionalKvPair(key, value))
        throw TextException(ToSBuf("missing required ", name, " parameter"), Here());
    if (strcmp(name, key) != 0)
        throw TextException(ToSBuf("expected required ", name, " parameter, but got ", key), Here());
    return T(name, value);
}
}

ProxyProtocol::OutgoingHttpConfig::OutgoingHttpConfig(ConfigParser &parser):
    srcAddr(MakeRequiredOption<AddrOption>("src_addr", parser)),
    dstAddr(MakeRequiredOption<AddrOption>("dst_addr", parser)),
    srcPort(MakeRequiredOption<PortOption>("src_port", parser)),
    dstPort(MakeRequiredOption<PortOption>("dst_port", parser))
{
    if (srcAddr.hasAddress() && dstAddr.hasAddress()) {
        Ip::Address adjustedSrc, adjustedDst;
        if (const auto err = adjustAddresses(adjustedSrc, adjustedDst, AccessLogEntryPointer()))
            throw TextException(*err, Here());
        srcAddr.setAddress(adjustedSrc);
        dstAddr.setAddress(adjustedDst);
    }

    parseTlvs(parser);
    aclList = parser.optionalAclList();
}

void
ProxyProtocol::OutgoingHttpConfig::dump(std::ostream &os)
{
    const auto separator = " ";
    os << srcAddr << separator << dstAddr << separator << srcPort << separator << dstPort <<
       AsList(tlvOptions).prefixedBy(separator).delimitedBy(separator);
    if (aclList) {
        // TODO: Use Acl::dump() after fixing the XXX in dump_acl_list().
        for (const auto &item: ToTree(aclList).treeDump("if", &Acl::AllowOrDeny)) {
            if (item.cmp("\n") == 0) // treeDump() adds this suffix
                continue;
            os << separator << item;
        }
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
    if (const auto err = adjustAddresses(src,dst, al))
        debugs(17, DBG_IMPORTANT, *err);
    src.port(srcPort.port(al).value_or(0));
    dst.port(dstPort.port(al).value_or(0));
}

void
ProxyProtocol::OutgoingHttpConfig::fillTlvs(Tlvs &tlvs, const AccessLogEntryPointer &al) const
{
    for (const auto &t : tlvOptions) {
        if (const auto v = t.tlvValue(al))
            tlvs.emplace_back(t.tlvType(), *v);
    }
}

/// converts the configured src_addr/dst_addr pair (having maybe unknown addresses or
/// addresses with mismatching families) into a pair of addresses with matching families.
/// \returns an error message if encountered a mismatching address family, or nullopt
std::optional<SBuf>
ProxyProtocol::OutgoingHttpConfig::adjustAddresses(Ip::Address &adjustedSrc, Ip::Address &adjustedDst, const AccessLogEntryPointer &al)
{
    auto src = srcAddr.address(al);
    auto dst = dstAddr.address(al);

    // source and/or destination are unknown
    // either configured as "-" or could not parse format codes
    if (!src && !dst) {
        // IPv4 by default
        adjustedSrc = Ip::Address::AnyAddrIPv4();
        adjustedDst = Ip::Address::AnyAddrIPv4();
        return std::nullopt;
    } else if (!src) {
        adjustedSrc = dst->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        adjustedDst = *dst;
        return std::nullopt;
    } else if (!dst) {
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        return std::nullopt;
    }

    // source and destination are known

    // source and destination have the same address family
    if (src->isIPv4() == dst->isIPv4()) {
        adjustedSrc = *src;
        adjustedDst = *dst;
        return std::nullopt;
    }

    // source and destination have different address family
    if (src->isAnyAddr() && !dst->isAnyAddr()) {
        adjustedSrc = dst->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        adjustedDst = *dst;
    } else {
        adjustedSrc = *src;
        adjustedDst = src->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
    }

    return ToSBuf("Address family mismatch: ", srcAddr.name(), "(", *src, ") vs. ", dstAddr.name(), "(", *dst, ")");
}

void
ProxyProtocol::OutgoingHttpConfig::parseTlvs(ConfigParser &parser)
{
    char *key = nullptr;
    char *value = nullptr;
    while (parser.optionalKvPair(key, value)) {
        const auto &current = tlvOptions.emplace_back(key, value);

        // the number of configured TLV options should not preclude a simple linear search
        const auto found = std::find_if(tlvOptions.begin(), tlvOptions.end(), [&](const auto &option) {
            /// Whether the previously parsed option is likely to produce the
            /// same bytes on-the-wire as the current one. We ignore superficial
            /// differences such as type ID letters "case" and value quoting.
            return option.tlvType() == current.tlvType() && option.format().specs == current.format().specs;
        });
        Assure(found != tlvOptions.end()); // we ought to find `current` (at least)
        if (&(*found) != &current)
            throw TextException(ToSBuf("duplicate TLV option: ", current), Here());
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

