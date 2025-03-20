/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H
#define SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H

#include "acl/forward.h"
#include "format/forward.h"
#include "ip/Address.h"
#include "log/forward.h"
#include "proxyp/Elements.h"
#include "proxyp/forward.h"

#include <list>
#include <iosfwd>
#include <optional>

class ConfigParser;

namespace ProxyProtocol {

/// A name=value parameter of an http_outgoing_proxy_protocol directive
/// configuring a PROXY protocol header field (pseudo header or TLV).
/// \tparam T determines the type of a successfully parsed header field value
template <typename T>
class FieldConfig final
{
public:
    /// a PROXY protocol header field value (when known) or nil (otherwise)
    using Value = std::optional<T>;

    FieldConfig(const char *aName, const char *logformatSpecs);
    ~FieldConfig();
    FieldConfig(FieldConfig &&) = delete;

    /// A "key" part of our "key=value" configuration. For options accepting
    /// multiple `key` spelling variations, uses canonical spelling.
    const char *name() const;

    /// compiled value specs
    const auto &format() const { return *value_; }

    /// Raw PROXY protocol header field value for the given transaction. Since
    /// PROXY protocol header fields must satisfy certain relationships,
    /// individual values returned by this method may need further adjustments.
    /// \sa OutgoingHttpConfig::adjustAddresses()
    Value valueToSend(const AccessLogEntryPointer &al) const;

    /// known-in-advance valueToSend() result (or nil)
    const auto &cachedValue() const { return cachedValue_; }

    /// (re)set valueToSend() result to a known value
    void cacheValue(const Value &v) { cachedValue_ = v; }

    /// reports configuration using squid.conf syntax
    void dump(std::ostream &) const;

private:

    void parseLogformat(const char *name, const char *logformat);

    /// applies logformat to the given transaction, expanding %codes as needed
    SBuf assembleValue(const AccessLogEntryPointer &al) const;

    /// converts given logformat-printed (by assembleValue()) string to Value
    Value parseAssembledValue(const SBuf &) const;

    /// informs admin of a value assembling error
    std::nullopt_t valueAssemblingFailure() const;

    Format::Format *value_; ///< compiled value format

    /// stored parseAssembledValue() result for constant value_ (or nil)
    std::optional<Value> cachedValue_;
};

/// \copydoc FieldConfig::dump(); TODO: Adjust if Doxygen cannot find this reference
template <typename T>
inline auto &operator <<(std::ostream &os, const FieldConfig<T> &o) { o.dump(os); return os; }

/// an http_outgoing_proxy_protocol directive configuration
class OutgoingHttpConfig
{
public:
    using Tlvs =  std::vector<Two::Tlv>;

    explicit OutgoingHttpConfig(ConfigParser &);

    void dump(std::ostream &);

    void fill(ProxyProtocol::Header &header, const AccessLogEntryPointer &);

    /// restrict logging to matching transactions
    ACLList *aclList = nullptr;

private:
    void parseTlvs(ConfigParser &);
    void fillAddresses(Ip::Address &src, Ip::Address &dst, const AccessLogEntryPointer &);
    void fillTlvs(Tlvs &, const AccessLogEntryPointer &) const;

    void parsePort(const char *optionName);
    std::optional<SBuf> adjustAddresses(std::optional<Ip::Address> &source, std::optional<Ip::Address> &destination);

    FieldConfig<Ip::Address> srcAddr;
    FieldConfig<Ip::Address> dstAddr;
    FieldConfig<uint16_t> srcPort;
    FieldConfig<uint16_t> dstPort;

    using TlvOptions = std::list< FieldConfig<SBuf> >;
    TlvOptions tlvOptions; // the list TLVs
};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H */

