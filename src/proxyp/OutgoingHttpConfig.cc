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

template <typename T>
ProxyProtocol::FieldConfig<T>::FieldConfig(const char * const name, const char * const logformat):
    value_(nullptr)
{
    parseLogformat(name, logformat);
    Assure(value_);
    if (!value_->isConstant()) {
        const auto assembledValue = assembleValue(AccessLogEntryPointer());
        cacheValue(parseAssembledValue(assembledValue));
    }
}

template <typename T>
ProxyProtocol::FieldConfig<T>::~FieldConfig()
{
    delete value_;
}

template <typename T>
const char *
ProxyProtocol::FieldConfig<T>::name() const
{
    Assure(value_);
    Assure(value_->name);
    return value_->name;
}

template <typename T>
void
ProxyProtocol::FieldConfig<T>::dump(std::ostream &os) const
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
template <typename T>
void
ProxyProtocol::FieldConfig<T>::parseLogformat(const char * const name, const char * const logformat)
{
    Assure(!value_);
    auto format = std::unique_ptr<Format::Format>(new Format::Format(name));
    if (!format->parse(logformat)) {
        throw TextException(ToSBuf("failed to parse logformat specs: ", logformat), Here());
    }
    value_ = format.release();
}

template <typename T>
std::nullopt_t
ProxyProtocol::FieldConfig<T>::valueAssemblingFailure() const
{
    debugs(17, DBG_IMPORTANT, "WARNING: Failed to compute the value of http_outgoing_proxy_protocol " << name() << " parameter" <<
           Debug::Extra << "problem: " << CurrentException);
    return std::nullopt;
}

template <typename T>
SBuf
ProxyProtocol::FieldConfig<T>::assembleValue(const AccessLogEntryPointer &al) const
{
    Assure(value_);
    static MemBuf mb;
    mb.reset();
    value_->assemble(mb, al, 0);
    return SBuf(mb.content());
}

template <typename T>
typename ProxyProtocol::FieldConfig<T>::Value
ProxyProtocol::FieldConfig<T>::valueToSend(const AccessLogEntryPointer &al) const
{
    if (cachedValue_)
        return *cachedValue_;

    try {
        const auto assembledValue = assembleValue(al);
        return parseAssembledValue(assembledValue);
    } catch (...) {
        return valueAssemblingFailure(); // XXX: Rename
    }
}

template <>
ProxyProtocol::FieldConfig<Ip::Address>::Value
ProxyProtocol::FieldConfig<Ip::Address>::parseAssembledValue(const SBuf &val) const
{
    if (val == Format::Dash)
        return std::nullopt;

    const auto addr = Ip::Address::Parse(SBuf(val).c_str());
    if (!addr)
        throw TextException(ToSBuf("Cannot parse '", val, "' as ", name()), Here());
    return addr;
}

template <>
ProxyProtocol::FieldConfig<uint16_t>::Value
ProxyProtocol::FieldConfig<uint16_t>::parseAssembledValue(const SBuf &val) const
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

template <>
ProxyProtocol::FieldConfig<SBuf>::Value
ProxyProtocol::FieldConfig<SBuf>::parseAssembledValue(const SBuf &val) const
{
    // TLVs do not treat Format::Dash values specially

    const auto maxLength = std::numeric_limits<uint16_t>::max();
    if (val.length() > maxLength)
        throw TextException(ToSBuf("Expected a TLV value with length not exceeding ", maxLength, " but got ", val.length(), " bytes"), Here());
    return val;
}

namespace ProxyProtocol
{
/// XXX: Document
template <typename Value>
static FieldConfig<Value>
MakeRequiredField(const char * const name, ConfigParser &parser)
{
    char *key = nullptr;
    char *value = nullptr;
    if(!parser.optionalKvPair(key, value))
        throw TextException(ToSBuf("missing required ", name, " parameter"), Here());
    if (strcmp(name, key) != 0)
        throw TextException(ToSBuf("expected required ", name, " parameter, but got ", key), Here());
    return FieldConfig<Value>(name, value);
}
}

ProxyProtocol::OutgoingHttpConfig::OutgoingHttpConfig(ConfigParser &parser):
    srcAddr(MakeRequiredField<Ip::Address>("src_addr", parser)),
    dstAddr(MakeRequiredField<Ip::Address>("dst_addr", parser)),
    srcPort(MakeRequiredField<uint16_t>("src_port", parser)),
    dstPort(MakeRequiredField<uint16_t>("dst_port", parser))
{
    auto s = srcAddr.cachedValue();
    auto d = dstAddr.cachedValue();
    if (s && d) {
        if (const auto err = adjustAddresses(*s, *d))
            throw TextException(*err, Here());
        // update cache using _adjusted_ values; they will never change
        srcAddr.cacheValue(*s);
        dstAddr.cacheValue(*d);
    }

    parseTlvs(parser);
    aclList = parser.optionalAclList();
}

void
ProxyProtocol::OutgoingHttpConfig::dump(std::ostream &os)
{
    const auto separator = " ";
    os << srcAddr << separator << dstAddr << separator << srcPort << separator << dstPort <<
       AsList(tlvConfigs).prefixedBy(separator).delimitedBy(separator);
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
    auto s = srcAddr.valueToSend(al);
    auto d = dstAddr.valueToSend(al);
    if (const auto err = adjustAddresses(s, d))
        debugs(17, DBG_IMPORTANT, *err);

    src = s.value();
    dst = d.value();
    src.port(srcPort.valueToSend(al).value_or(0));
    dst.port(dstPort.valueToSend(al).value_or(0));
}

void
ProxyProtocol::OutgoingHttpConfig::fillTlvs(Tlvs &tlvs, const AccessLogEntryPointer &al) const
{
    for (const auto &t: tlvConfigs) {
        const auto type = strtol(t.name(), nullptr, 0);
        Assure(type >= std::numeric_limits<Two::Tlv::value_type>::min());
        Assure(type <= std::numeric_limits<Two::Tlv::value_type>::max());
        const auto v = t.valueToSend(al);
        tlvs.emplace_back(type, v.value_or(Format::Dash));
    }
}

/// converts the configured src_addr/dst_addr pair (having maybe unknown addresses or
/// addresses with mismatching families) into a pair of addresses with matching families.
/// \returns an error message if encountered a mismatching address family, or nullopt
std::optional<SBuf>
ProxyProtocol::OutgoingHttpConfig::adjustAddresses(std::optional<Ip::Address> &s, std::optional<Ip::Address> &d)
{
    // TODO: Find a way to reduce code duplication inside this method

    if (!s && !d) {
        // source and destination are unknown: default to IPv4
        s = d = Ip::Address::AnyAddrIPv4();
        return std::nullopt;
    } else if (!s) {
        // only source is unknown: use known destination address family
        s = d->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        return std::nullopt;
    } else if (!d) {
        // only destination is unknown: use known source address family
        d = s->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        return std::nullopt;
    }

    // source and destination are known
    Assure(s && d);
    if (s->isIPv4() == d->isIPv4()) {
        // source and destination have the same address family
        return std::nullopt;
    }

    // Known source and destination have different address families. We must
    // overwrite one of the addresses. Avoid overwriting a specific address (if
    // possible) or preserve specific source address (otherwise).
    if (d->isAnyAddr()) {
        // * specific source address and "any" destination
        // * "any" source address and "any" destination
        d = s->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        return std::nullopt;
    } else if (s->isAnyAddr()) {
        // * "any" source address and specific destination
        s = d->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        return std::nullopt;
    } else {
        // * specific source address and specific destination
        const auto originalDestination = *d;
        d = s->isIPv4() ? Ip::Address::AnyAddrIPv4() : Ip::Address::AnyAddrIPv6();
        return ToSBuf("Address family mismatch: ",
                      srcAddr, " (expanded as ", *s, ") vs. ",
                      dstAddr, " (expanded as ", originalDestination, ")");
    }
}

void
ProxyProtocol::OutgoingHttpConfig::parseTlvs(ConfigParser &parser)
{
    char *key = nullptr;
    char *value = nullptr;
    while (parser.optionalKvPair(key, value)) {
        const auto &current = tlvConfigs.emplace_back(key, value);

        // validate TLV "type" spelling
        const auto typeMin = 0xE0;
        const auto typeMax = 0xEF;
        int64_t t = -1;
        auto tok = Parser::Tokenizer(SBuf(current.name())); // TODO: Convert Format::Format::name to SBuf
        // XXX: "0" does not mean "decimal or hex"
        if (!tok.int64(t, 0, false) || (t < typeMin || t > typeMax))
            throw TextException(ToSBuf("Expected TLV type as a decimal or hex number in the [0xE0, 0xEF] range but got ", current.name()), Here());
        // We use strtol() at runtime to avoid expensive to-SBuf conversion
        // above. TODO: Consider caching parsed value.
        Assure(t == strtol(current.name(), nullptr, 0));

        // the number of configured TLVs should not preclude a simple linear search
        const auto found = std::find_if(tlvConfigs.begin(), tlvConfigs.end(), [&](const auto &tlvConfig) {
            /// Whether previously parsed tlvConfig is likely to produce the
            /// same bytes on-the-wire as the current one. We ignore superficial
            /// differences such as type ID letters "case" and value quoting.
            return strcasecmp(tlvConfig.name(), current.name()) == 0 && tlvConfig.format().specs == current.format().specs;
        });
        Assure(found != tlvConfigs.end()); // we ought to find `current` (at least)
        if (&(*found) != &current)
            throw TextException(ToSBuf("duplicate TLV specs: ", current), Here());
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

