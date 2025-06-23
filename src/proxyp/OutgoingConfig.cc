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
#include "log/RecordTime.h"
#include "MemBuf.h"
#include "parser/Tokenizer.h"
#include "proxyp/Header.h"
#include "proxyp/OutgoingConfig.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"

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
        RecordTime recordTime; // unused by isStatic() formats
        const auto assembledValue = assembleValue(nullptr, recordTime);
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
ProxyProtocol::FieldConfig<T>::assembleValue(const AccessLogEntryPointer &al, const RecordTime &recordTime) const
{
    static MemBuf mb;
    mb.reset();
    format_->assemble(mb, al, 0, recordTime);
    return SBuf(mb.content());
}

template <typename T>
typename ProxyProtocol::FieldConfig<T>::Value
ProxyProtocol::FieldConfig<T>::makeValue(const AccessLogEntryPointer &al, const RecordTime &recordTime) const
{
    if (cachedValue_)
        return *cachedValue_;

    try {
        const auto assembledValue = assembleValue(al, recordTime);
        return parseAssembledValue(assembledValue);
    } catch (...) {
        debugs(17, DBG_IMPORTANT, "WARNING: Failed to compute the value of proxy_protocol_outgoing " << name() << " parameter" <<
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

/// OutgoingConfig member initialization helper for required name=value fields
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

ProxyProtocol::OutgoingConfig::OutgoingConfig(ConfigParser &parser):
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

ProxyProtocol::OutgoingConfig::~OutgoingConfig()
{
    aclDestroyAclList(&aclList);
}

void
ProxyProtocol::OutgoingConfig::dump(std::ostream &os, const char * const directiveName) const
{
    const auto separator = " ";
    os << directiveName << separator <<
       sourceIp << separator << destinationIp << separator <<
       sourcePort << separator << destinationPort <<
       AsList(tlvs).prefixedBy(separator).delimitedBy(separator);
    if (aclList) {
        // TODO: Use Acl::dump() after fixing the XXX in dump_acl_list().
        for (const auto &item: aclList->treeDump("if", &Acl::AllowOrDeny)) {
            if (item.cmp("\n") == 0) // treeDump() adds this suffix
                continue;
            os << separator << item;
        }
    }
    os << '\n';
}

void
ProxyProtocol::OutgoingConfig::fill(ProxyProtocol::Header &header, const AccessLogEntryPointer &al, const RecordTime &recordTime) const
{
    if (!header.localConnection()) {
        auto s = sourceIp.makeValue(al, recordTime);
        auto d = destinationIp.makeValue(al, recordTime);
        if (const auto err = adjustIps(s, d))
            debugs(17, DBG_IMPORTANT, "ERROR: " << *err);
        header.sourceAddress = s.value();
        header.destinationAddress = d.value();

        header.sourceAddress.port(sourcePort.makeValue(al, recordTime).value_or(0));
        header.destinationAddress.port(destinationPort.makeValue(al, recordTime).value_or(0));
    }

    for (const auto &tlv: tlvs) {
        const auto type = strtol(tlv.name(), nullptr, 10);
        Assure(type >= std::numeric_limits<Two::Tlv::value_type>::min());
        Assure(type <= std::numeric_limits<Two::Tlv::value_type>::max());
        if (const auto v = tlv.makeValue(al, recordTime))
            header.tlvs.emplace_back(type, *v);
    }
}

/// converts the configured src_addr/dst_addr pair (having maybe unknown addresses or
/// addresses with mismatching families) into a pair of addresses with matching families.
/// \returns an error message if encountered a mismatching address family, or nullopt
std::optional<SBuf>
ProxyProtocol::OutgoingConfig::adjustIps(std::optional<Ip::Address> &s, std::optional<Ip::Address> &d) const
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
ProxyProtocol::OutgoingConfig::parseTlvs(ConfigParser &parser)
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

/* ProxyProtocol::OutgoingConfigs */

const ProxyProtocol::OutgoingConfig *
ProxyProtocol::OutgoingConfigs::match(const HttpRequestPointer &request, const AccessLogEntryPointer &al) const
{
    ACLFilledChecklist ch(nullptr, request.getRaw());
    ch.al = al;
    ch.syncAle(request.getRaw(), nullptr);

    for (const auto &config: configs_) {
        if (const auto &aclList = config.aclList) {
            ch.changeAcl(aclList);
            if (!ch.fastCheck().allowed())
                continue;
            // else fall through to return a matching config
        }
        return &config;
    }

    // no configuration matched
    return nullptr;
}

void
ProxyProtocol::OutgoingConfigs::dump(std::ostream &os, const char * const directiveName) const
{
    for (const auto &config: configs_)
        config.dump(os, directiveName);
}

namespace Configuration {

template <>
ProxyProtocol::OutgoingConfigs *
Configuration::Component<ProxyProtocol::OutgoingConfigs*>::Parse(ConfigParser &parser)
{
    // XXX: A hack to work around the lack of REPETITIONS:update support.
    if (!Config.proxyProtocolOutgoing)
        Config.proxyProtocolOutgoing = new ProxyProtocol::OutgoingConfigs();

    Config.proxyProtocolOutgoing->emplace(parser);
    return Config.proxyProtocolOutgoing;
}

template <>
void
Configuration::Component<ProxyProtocol::OutgoingConfigs*>::Print(std::ostream &os, ProxyProtocol::OutgoingConfigs* const & cfg, const char * const directiveName)
{
    Assure(cfg);
    cfg->dump(os, directiveName);
}

template <>
void
Configuration::Component<ProxyProtocol::OutgoingConfigs*>::Free(ProxyProtocol::OutgoingConfigs * const cfg)
{
    delete cfg;
}

} // namespace Configuration

