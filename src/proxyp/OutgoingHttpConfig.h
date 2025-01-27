/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H
#define SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H

#include <acl/forward.h>
#include <ip/Address.h>
#include <log/forward.h>
#include <proxyp/Elements.h>

#include <iosfwd>
#include <optional>

class ConfigParser;

namespace ProxyProtocol {

/// an option for http_outgoing_proxy_protocol directive
class Option : public RefCountable
{
public:
    Option(const char *aName, const char *aVal, bool quoted);
    ~Option() { delete valueFormat; }

    /// expands logformat %macros (quoted values)
    void format(const AccessLogEntryPointer &al);

    SBuf theName;  ///< Configured option name
    SBuf theValue; ///< Configured option value, possibly with %macros.

protected:
    virtual void parse(const SBuf &) = 0;

    Format::Format *valueFormat; ///< compiled value format

    /// The expanded value produced by format(), empty for non-quoted values.
    SBuf theFormattedValue;
private:
    /// parses the value as a logformat string
    void parseFormat();
};

class AddrOption : public Option
{
public:
	AddrOption(const char *aName, const char *aVal, bool quoted);

	Ip::Address address() const { Assure(address_); return *address_; }
protected:
    void parse(const SBuf &) override;

	std::optional<Ip::Address> address_;

	friend class OutgoingHttpConfig;
};

class PortOption : public Option
{
public:
	PortOption(const char *aName, const char *aVal, bool quoted);

	unsigned short port() const { Assure(port_); return *port_; }

protected:
    void parse(const SBuf &) override;

	std::optional<unsigned short> port_;
};

class TlvOption : public Option
{
public:
    typedef RefCount<TlvOption> Pointer;

	TlvOption(const char *aName, const char *aVal, bool quoted);

	SBuf value() const { return theFormattedValue.isEmpty() ? theValue : theFormattedValue; }
	uint8_t type() const { return type_; }

protected:
    void parse(const SBuf &) override;

    uint8_t type_;
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
    void getAddresses(Ip::Address &src, Ip::Address &dst, const AccessLogEntryPointer &);
    void getTlvs(Tlvs &, const AccessLogEntryPointer &) const;

    void parseAddress(const char *optionName);
    void parsePort(const char *optionName);
    const char *requiredValue(const char *optionName);
    void adjustAddresses(bool enforce);

    AddrOption *srcAddr;
    AddrOption *dstAddr;
    PortOption *srcPort;
    PortOption *dstPort;
    using TlvOptions = std::vector<TlvOption::Pointer>;
    TlvOptions tlvOptions; // all configured options, with fixed order for required options
};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H */

