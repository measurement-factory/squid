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

/// a name=value option for the http_outgoing_proxy_protocol directive
class Option
{
public:
    Option(const char *aName, ConfigParser &);
    Option(const char *aName, const char *aVal);
    virtual ~Option(); // XXX: A waste because we never delete polymorphically.
    Option(Option &&) = delete;

    /// A "key" part of our "key=value" configuration. For options accepting
    /// multiple `key` spelling variations, uses canonical spelling.
    const char *name() const;

    /// compiled value specs
    const auto &format() const { return *value_; }

    /// reports configuration using squid.conf syntax
    void dump(std::ostream &) const;

protected:
    /// applies logformat to the given transaction, expanding %codes as needed
    SBuf assembleValue(const AccessLogEntryPointer &al) const;

    /// informs admin of a value assembling error
    std::nullopt_t valueAssemblingFailure() const;

    Format::Format *value_; ///< compiled value format

private:
    void parseLogformat(const char *name, const char *logformat);
};

/// \copydoc Option::dump()
inline auto &operator <<(std::ostream &os, const Option &o) { o.dump(os); return os; }

/// an address option for http_outgoing_proxy_protocol directive
class AddrOption : public Option
{
public:
    using Addr = std::optional<Ip::Address>;

    AddrOption(const char *aName, ConfigParser &);

    Addr address(const AccessLogEntryPointer &al) const;
    bool hasAddress() const { return address_.has_value(); }
    void setAddress(const Ip::Address &addr) { address_ = addr; }

protected:
    std::optional<Ip::Address> parseAddr(const SBuf &) const;

    Addr address_; ///< transaction-independent source or destination address
};

/// a port option for http_outgoing_proxy_protocol directive
class PortOption : public Option
{
public:
    using Port = std::optional<uint16_t>;

    PortOption(const char *aName, ConfigParser &);

    Port port(const AccessLogEntryPointer &al) const;

protected:
    Port parsePort(const SBuf &val) const;

    Port port_; ///< transaction-independent source or destination address port
};

/// a TLV option for http_outgoing_proxy_protocol directive
class TlvOption : public Option
{
public:
    using TlvType = uint8_t;
    using TlvValue = std::optional<SBuf>;

    TlvOption(const char *aName, const char *aVal);

    TlvValue tlvValue(const AccessLogEntryPointer &al) const;
    TlvType tlvType() const { return tlvType_; }

protected:
    TlvType tlvType_;
    TlvValue tlvValue_; ///< transaction-independent TLV value
};

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

    void parseAddress(const char *optionName);
    void parsePort(const char *optionName);
    std::optional<SBuf> adjustAddresses(Ip::Address &adjustedSrc, Ip::Address &adjustedDst, const AccessLogEntryPointer &al);

    AddrOption srcAddr;
    AddrOption dstAddr;
    PortOption srcPort;
    PortOption dstPort;

    using TlvOptions = std::list<TlvOption>;
    TlvOptions tlvOptions; // the list TLVs
};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H */

