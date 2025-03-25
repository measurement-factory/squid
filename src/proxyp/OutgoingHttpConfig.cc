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

namespace ProxyProtocol
{

// TODO: Add logformat parameter to Format constructor and parse there instead.
/// parses named logformat specification
static std::unique_ptr<Format::Format>
ParseLogformat(const char * const name, const char * const logformat)
{
    Assure(logformat);

    // TODO: Support sending empty TLVs. Today, we ban empty logformat specs
    // because Format::assemble() misinterprets them as a single "-" field.
    if (!*logformat)
        throw TextException(ToSBuf("empty logformat specs are not supported for ", name, "=..."), Here());

    auto format = std::make_unique<Format::Format>(name);
    if (!format->parse(logformat))
        throw TextException(ToSBuf("failed to parse logformat specs: ", logformat), Here());
    return format;
}

} // namespace ProxyProtocol

template <typename T>
ProxyProtocol::FieldConfig<T>::FieldConfig(const char * const name, const char * const logformat):
    format_(ParseLogformat(name, logformat))
{
    Assure(format_);
    if (format_->isStatic()) {
        const auto assembledValue = assembleValue(nullptr);
        cacheValue(parseAssembledValue(assembledValue));
    }
}

template <typename T>
const char *
ProxyProtocol::FieldConfig<T>::name() const
{
    Assure(format_->name);
    return format_->name;
}

template <typename T>
void
ProxyProtocol::FieldConfig<T>::dump(std::ostream &os) const
{
    os << name() << '=';
    os << '"';
    format_->dumpDefinition(os);
    os << '"';
}

/// applies logformat to the given transaction, expanding %codes as needed
template <typename T>
SBuf
ProxyProtocol::FieldConfig<T>::assembleValue(const AccessLogEntryPointer &al) const
{
    static MemBuf mb;
    mb.reset();
    format_->assemble(mb, al, 0);
    return SBuf(mb.content());
}

template <typename T>
typename ProxyProtocol::FieldConfig<T>::Value
ProxyProtocol::FieldConfig<T>::makeValue(const AccessLogEntryPointer &al) const
{
    if (cachedValue_)
        return *cachedValue_;

    try {
        const auto assembledValue = assembleValue(al);
        return parseAssembledValue(assembledValue);
    } catch (...) {
        debugs(17, DBG_IMPORTANT, "WARNING: Failed to compute the value of http_outgoing_proxy_protocol " << name() << " parameter" <<
               Debug::Extra << "problem: " << CurrentException);
        return std::nullopt;
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

/// OutgoingHttpConfig member initialization helper for required name=value fields
template <typename Value>
static FieldConfig<Value>
MakeRequiredField(const char * const name, ConfigParser &parser)
{
    char *key = nullptr;
    char *value = nullptr;
    if (!parser.optionalKvPair(key, value))
        throw TextException(ToSBuf("missing required ", name, " parameter"), Here());
    if (strcmp(name, key) != 0)
        throw TextException(ToSBuf("expected required ", name, " parameter, but got ", key), Here());
    if (!parser.LastTokenWasQuoted())
        throw TextException(ToSBuf(name, " parameter value (i.e. logformat format specs) must be \"quoted\""), Here());
    return FieldConfig<Value>(name, value);
}

} // namespace ProxyProtocol

ProxyProtocol::OutgoingHttpConfig::OutgoingHttpConfig(ConfigParser &parser):
    sourceIp(MakeRequiredField<Ip::Address>("src_addr", parser)),
    destinationIp(MakeRequiredField<Ip::Address>("dst_addr", parser)),
    sourcePort(MakeRequiredField<uint16_t>("src_port", parser)),
    destinationPort(MakeRequiredField<uint16_t>("dst_port", parser))
{
    auto s = sourceIp.cachedValue();
    auto d = destinationIp.cachedValue();
    if (s && d) {
        if (const auto err = adjustIps(*s, *d))
            throw TextException(*err, Here());
        // update cache using _adjusted_ values; they will never change
        sourceIp.cacheValue(*s);
        destinationIp.cacheValue(*d);
    }

    parseTlvs(parser);
    aclList = parser.optionalAclList();
}

ProxyProtocol::OutgoingHttpConfig::~OutgoingHttpConfig()
{
    aclDestroyAclList(&aclList);
}

void
ProxyProtocol::OutgoingHttpConfig::dump(std::ostream &os)
{
    const auto separator = " ";
    os << sourceIp << separator << destinationIp << separator << sourcePort << separator << destinationPort <<
       AsList(tlvs).prefixedBy(separator).delimitedBy(separator);
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
    if (!header.localConnection()) {
        auto s = sourceIp.makeValue(al);
        auto d = destinationIp.makeValue(al);
        if (const auto err = adjustIps(s, d))
            debugs(17, DBG_IMPORTANT, "ERROR: " << *err);
        header.sourceAddress = s.value();
        header.destinationAddress = d.value();

        header.sourceAddress.port(sourcePort.makeValue(al).value_or(0));
        header.destinationAddress.port(destinationPort.makeValue(al).value_or(0));
    }

    for (const auto &tlv: tlvs) {
        const auto type = strtol(tlv.name(), nullptr, 10);
        Assure(type >= std::numeric_limits<Two::Tlv::value_type>::min());
        Assure(type <= std::numeric_limits<Two::Tlv::value_type>::max());
        if (const auto v = tlv.makeValue(al))
            header.tlvs.emplace_back(type, *v);
    }
}

/// converts the configured src_addr/dst_addr pair (having maybe unknown addresses or
/// addresses with mismatching families) into a pair of addresses with matching families.
/// \returns an error message if encountered a mismatching address family, or nullopt
std::optional<SBuf>
ProxyProtocol::OutgoingHttpConfig::adjustIps(std::optional<Ip::Address> &s, std::optional<Ip::Address> &d)
{
    const auto anyLike = [](const Ip::Address &ip) { return Ip::Address::Any(ip.family()); };

    if (!s && !d) {
        // source and destination are unknown: default to IPv4
        s = d = Ip::Address::AnyIPv4();
        return std::nullopt;
    } else if (!s) {
        // only source is unknown: use known destination address family
        s = anyLike(*d);
        return std::nullopt;
    } else if (!d) {
        // only destination is unknown: use known source address family
        d = anyLike(*s);
        return std::nullopt;
    }

    // source and destination are known
    Assure(s && d);
    if (s->family() == d->family()) {
        // source and destination have the same address family
        return std::nullopt;
    }

    // Known source and destination have different address families. We must
    // overwrite one of the addresses. Avoid overwriting a specific address (if
    // possible) or preserve specific source address (otherwise).
    if (d->isAnyAddr()) {
        // * specific source address and "any" destination
        // * "any" source address and "any" destination
        d = anyLike(*s);
        return std::nullopt;
    } else if (s->isAnyAddr()) {
        // * "any" source address and specific destination
        s = anyLike(*d);
        return std::nullopt;
    } else {
        // * specific source address and specific destination
        const auto originalDestination = *d;
        d = anyLike(*s);
        return ToSBuf("Address family mismatch: ",
                      sourceIp, " (expanded as ", *s, ") vs. ",
                      destinationIp, " (expanded as ", originalDestination, ")");
    }
}

void
ProxyProtocol::OutgoingHttpConfig::parseTlvs(ConfigParser &parser)
{
    char *key = nullptr;
    char *value = nullptr;
    while (parser.optionalKvPair(key, value)) {
        const auto &current = tlvs.emplace_back(key, value);

        // validate TLV "type" spelling
        const auto typeMin = 0xE0;
        const auto typeMax = 0xEF;
        int64_t t = -1;
        auto tok = Parser::Tokenizer(SBuf(current.name())); // TODO: Convert Format::Format::name to SBuf
        // prohibit leading zeros to avoid misinterpreting/accepting octal
        // values and to simplify potential future hex value support
        if (tok.skip('0') || !tok.int64(t, 10, false) || tok.remaining().length() || (t < typeMin || t > typeMax))
            throw TextException(ToSBuf("Expected TLV type as a decimal number in the [224, 239] range but got ", current.name()), Here());
        // We use strtol() at runtime to avoid expensive to-SBuf conversion
        // above. TODO: Consider caching parsed value.
        Assure(t == strtol(current.name(), nullptr, 10));

        // the number of configured TLVs should not preclude a simple linear search
        const auto found = std::find_if(tlvs.begin(), tlvs.end(), [&](const auto &tlv) {
            /// Whether previously parsed tlv is likely to produce the same
            /// bytes on-the-wire as the current one. We ignore superficial
            /// differences such as type ID letters "case" (for when we start
            /// supporting hex type IDs like 0xEe=...) and value quoting.
            return strcasecmp(tlv.name(), current.name()) == 0 && tlv.format().specs == current.format().specs;
        });
        Assure(found != tlvs.end()); // we ought to find `current` (at least)
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
    Assure(cfg);
    cfg->dump(os);
}

template <>
void
Configuration::Component<ProxyProtocol::OutgoingHttpConfig*>::Free(ProxyProtocol::OutgoingHttpConfig * const cfg)
{
    delete cfg;
}

} // namespace Configuration

