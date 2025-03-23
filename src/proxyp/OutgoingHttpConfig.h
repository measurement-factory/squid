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

#include <iosfwd>
#include <list>
#include <memory>
#include <optional>

class ConfigParser;

namespace ProxyProtocol {

/// A name=value parameter of an http_outgoing_proxy_protocol directive
/// configuring a PROXY protocol header field (pseudo header or TLV).
/// \tparam T determines the type of a successfully parsed header field value
template <typename T>
class FieldConfig
{
public:
    /// a PROXY protocol header field value (when known) or nil (otherwise)
    using Value = std::optional<T>;

    FieldConfig(const char *aName, const char *logformatSpecs);

    /// the "key" part of our "key=value" configuration
    const char *name() const;

    /// compiled value specs
    const auto &format() const { return *format_; }

    /// Raw PROXY protocol header field value for the given transaction. Since
    /// PROXY protocol header fields must satisfy certain relationship rules,
    /// individual values returned by this method may need further adjustments.
    /// \sa OutgoingHttpConfig::adjustIps()
    Value makeValue(const AccessLogEntryPointer &al) const;

    /// known-in-advance transaction-independent makeValue() result (or nil)
    const auto &cachedValue() const { return cachedValue_; }

    /// (re)set makeValue() result to a known transaction-independent value
    void cacheValue(const Value &v) { cachedValue_ = v; }

    /// reports configuration using squid.conf syntax
    void dump(std::ostream &) const;

private:
    SBuf assembleValue(const AccessLogEntryPointer &al) const;

    /// specializations of this method convert the given string to Value
    /// \param input is a logformat-printed by assembleValue() string
    Value parseAssembledValue(const SBuf &input) const;

    /// compiled value logformat specs; never nil
    const std::unique_ptr<Format::Format> format_;

    /// stored parseAssembledValue() result for isStatic() format_ (or nil)
    std::optional<Value> cachedValue_;
};

/// \copydoc FieldConfig::dump(); TODO: Adjust if Doxygen cannot find this reference
template <typename T>
inline auto &operator <<(std::ostream &os, const FieldConfig<T> &o) { o.dump(os); return os; }

/// an http_outgoing_proxy_protocol directive configuration
class OutgoingHttpConfig final
{
public:
    explicit OutgoingHttpConfig(ConfigParser &);
    ~OutgoingHttpConfig();

    void fill(Header &, const AccessLogEntryPointer &);

    void dump(std::ostream &);

    /// restrict logging to matching transactions
    ACLList *aclList = nullptr;

private:
    void parseTlvs(ConfigParser &);
    std::optional<SBuf> adjustIps(std::optional<Ip::Address> &source, std::optional<Ip::Address> &destination);

    FieldConfig<Ip::Address> sourceIp;
    FieldConfig<Ip::Address> destinationIp;
    FieldConfig<uint16_t> sourcePort;
    FieldConfig<uint16_t> destinationPort;

    using Tlvs = std::list< FieldConfig<SBuf> >;
    Tlvs tlvs; ///< configuration for generating TLV header fields
};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H */

