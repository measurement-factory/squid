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
#include <optional>

class ConfigParser;

namespace ProxyProtocol {

/// a name=value option for http_outgoing_proxy_protocol directive
class Option : public RefCountable
{
public:
    Option(const char *aName, const char *aVal, bool quoted);
    virtual ~Option();

    void dump(std::ostream &);

    SBuf theName;  ///< Configured option name
    SBuf theValue; ///< Configured option value, possibly with %macros.
    const bool theQuoted;

protected:
    /// \returns the value with expanded logformat %macros (quoted values)
    SBuf processFormat(const AccessLogEntryPointer &al) const;

    Format::Format *valueFormat; ///< compiled value format

private:
    /// parses the value as a logformat string
    void parseFormat();
};

std::ostream &
operator << (std::ostream &os, const Option &opt);

/// an address option for http_outgoing_proxy_protocol directive
class AddrOption : public Option
{
public:
    using Pointer =  RefCount<AddrOption>;
    using Addr = std::optional<Ip::Address>;

    AddrOption(const char *aName, const char *aVal, bool quoted);

    Addr address(const AccessLogEntryPointer &al) const;
    bool hasAddress() const { return address_.has_value(); }
    void setAddress(const Ip::Address &addr) { address_ = addr; }

protected:
    std::optional<Ip::Address> parseAddr(const SBuf &) const;

    Addr address_; ///< parsed address (for options without logformat %macros)
};

/// a port option for http_outgoing_proxy_protocol directive
class PortOption : public Option
{
public:
    using Pointer =  RefCount<PortOption>;
    using Port = std::optional<uint16_t>;

    PortOption(const char *aName, const char *aVal, bool quoted);

    Port port(const AccessLogEntryPointer &al) const;

protected:
    uint16_t parsePort(const SBuf &val) const;

    Port port_; ///< transaction-independent source or destination address port
};

/// a TLV option for http_outgoing_proxy_protocol directive
class TlvOption : public Option
{
public:
    using Pointer =  RefCount<TlvOption>;
    using TlvValue = std::optional<SBuf>;

    TlvOption(const char *aName, const char *aVal, bool quoted);

    TlvValue tlvValue(const AccessLogEntryPointer &al) const;
    uint8_t tlvType() const { return tlvType_; }

protected:
    uint8_t tlvType_; /// the parsed TLV type
    TlvValue tlvValue_; ///< the parsed TLV value (for options without logformat %macros)
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
    void parseOptions(ConfigParser &);
    void fillAddresses(Ip::Address &src, Ip::Address &dst, const AccessLogEntryPointer &);
    void fillTlvs(Tlvs &, const AccessLogEntryPointer &) const;

    void parseAddress(const char *optionName);
    void parsePort(const char *optionName);
    const char *requiredValue(const char *optionName);
    void adjustAddresses(Ip::Address &adjustedSrc, Ip::Address &adjustedDst, const AccessLogEntryPointer &al);

    AddrOption::Pointer srcAddr;
    AddrOption::Pointer dstAddr;
    PortOption::Pointer srcPort;
    PortOption::Pointer dstPort;
    using TlvOptions = std::vector<TlvOption::Pointer>;
    TlvOptions tlvOptions; // all configured options, with fixed order for required options
};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H */

