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

/// a name=value option for the http_outgoing_proxy_protocol directive
class Option : public RefCountable
{
public:
    Option(const char *aName, ConfigParser &);
    Option(const char *aName, const char *aVal, bool quoted);
    virtual ~Option();

    /// reports configuration using squid.conf syntax
    void dump(std::ostream &) const;

    SBuf name_; ///< the option name
    bool quoted_; ///< whether the option value is quoted

protected:
    /// \returns the value with expanded logformat %macros (quoted values)
    SBuf assembleValue(const AccessLogEntryPointer &al) const;

    Format::Format *value_; ///< compiled value format

private:
    /// parses the value as a logformat string
    void parseFormat(const char *);
};

/// \copydoc Option::dump()
inline auto &operator <<(std::ostream &os, const Option &o) { o.dump(os); return os; }

/// an address option for http_outgoing_proxy_protocol directive
class AddrOption : public Option
{
public:
    using Pointer =  RefCount<AddrOption>;
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
    using Pointer =  RefCount<PortOption>;
    using Port = std::optional<uint16_t>;

    PortOption(const char *aName, ConfigParser &);

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
    using TlvType = uint8_t;
    using TlvValue = std::optional<SBuf>;

    TlvOption(const char *aName, const char *aVal, bool quoted);

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
    void parseOptions(ConfigParser &);
    void fillAddresses(Ip::Address &src, Ip::Address &dst, const AccessLogEntryPointer &);
    void fillTlvs(Tlvs &, const AccessLogEntryPointer &) const;

    void parseAddress(const char *optionName);
    void parsePort(const char *optionName);
    std::optional<SBuf> adjustAddresses(Ip::Address &adjustedSrc, Ip::Address &adjustedDst, const AccessLogEntryPointer &al);

    AddrOption::Pointer srcAddr;
    AddrOption::Pointer dstAddr;
    PortOption::Pointer srcPort;
    PortOption::Pointer dstPort;

    using TlvOptions = std::vector<TlvOption::Pointer>;
    TlvOptions tlvOptions; // the list TLVs
};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H */

