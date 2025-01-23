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
#include <log/forward.h>

#include <iosfwd>

class ConfigParser;

namespace ProxyProtocol {

/// an option for http_outgoing_proxy_protocol directive
class Option : public RefCountable
{
public:
    typedef RefCount<Option> Pointer;

    explicit Option(const char *aName);
    Option(const char *aName, const char *aVal, bool quoted);
    ~Option() { delete valueFormat; }

    /// parses the value as a logformat string
    void parse();

    /// \return the formatted value with expanded logformat %macros (quoted values).
    /// \return the original value (non-quoted values).
    const SBuf &format(const AccessLogEntryPointer &al);

    SBuf theName;  ///< Configured option name
    SBuf theValue; ///< Configured option value, possibly with %macros.

private:
    Format::Format *valueFormat; ///< compiled value format

    /// The expanded value produced by format(), empty for non-quoted values.
    SBuf theFormattedValue;
};

/// an http_outgoing_proxy_protocol directive configuration
class OutgoingHttpConfig
{
public:
    explicit OutgoingHttpConfig(ConfigParser &);

    void dump(std::ostream &);

    void parseOptions(ConfigParser &);

    Ip::Address srcAddr(const AccessLogEntryPointer &al) const { return getAddr(al, 0, 2); }
    Ip::Address dstAddr(const AccessLogEntryPointer &al) const { return getAddr(al, 1, 3); }

    /// restrict logging to matching transactions
    ACLList *aclList = nullptr;

private:
    Ip::Address getAddr(const AccessLogEntryPointer &, const size_t addrIdx, const size_t portIdx) const;

    using Options = std::vector<Option::Pointer>;
    Options params; // all configured options, with fixed order for required options

};

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_OUTGOINGHTTPCONFIG_H */

