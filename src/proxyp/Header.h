/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PROXYP_HEADER_H
#define SQUID_SRC_PROXYP_HEADER_H

#include "base/RefCount.h"
#include "ip/Address.h"
#include "MemBuf.h"
#include "proxyp/Elements.h"
#include "sbuf/SBuf.h"

#include <vector>

namespace ProxyProtocol {

/// PROXY protocol v1 or v2 header
class Header: public RefCountable
{
public:
    typedef RefCount<Header> Pointer;
    typedef std::vector<Two::Tlv> Tlvs;

    Header(const SBuf &ver, const Two::Command cmd);

    /// HTTP header-like string representation of the header.
    /// The returned string has one line per pseudo header and
    /// one line per TLV (if any).
    SBuf toMime() const;

    /// \returns a delimiter-separated list of values of TLVs of the given type
    SBuf getValues(const uint32_t headerType, const char delimiter = ',') const;

    /// Searches for the first key=value pair occurrence within the
    /// value for the provided TLV type. Assumes that the TLV value
    /// is a delimiter-separated list.
    /// \returns the value of the found pair or the empty string.
    SBuf getElem(const uint32_t headerType, const char *member, const char delimiter) const;

    /// PROXY protocol version
    const SBuf &version() const { return version_; }

    /// whether source and destination addresses are valid addresses of the original "client" connection
    bool hasForwardedAddresses() const { return !localConnection() && hasAddresses(); }

    /// marks the header as lacking address information
    void ignoreAddresses() { ignoreAddresses_ = true; }

    /// whether the header relays address information (including LOCAL connections)
    bool hasAddresses() const { return !ignoreAddresses_; }

    /// \returns "4" or "6" if both source and destination addresses are IPv4 or IPv6
    /// \returns "mix" otherwise
    const SBuf &addressFamily() const;

    void packInto(MemBuf &mb) const;

    /// source address of the client connection
    Ip::Address sourceAddress;
    /// intended destination address of the client connection
    Ip::Address destinationAddress;
    /// empty in v1 headers and when ignored in v2 headers
    Tlvs tlvs;

private:
    /// Whether the connection over PROXY protocol is 'cmdLocal'.
    /// Such connections are established without being relayed.
    /// Received addresses and TLVs are discarded in this mode.
    bool localConnection() const { return command_ == Two::cmdLocal; }

    /// PROXY protocol version
    SBuf version_;

    /// for v2 headers: the command field
    /// for v1 headers: Two::cmdProxy
    Two::Command command_;

    /// true if the header relays no address information
    bool ignoreAddresses_;
};

namespace One {
/// magic octet prefix for PROXY protocol version 1
inline const auto &
Magic()
{
    static const auto magic = new SBuf("PROXY", 5);
    return *magic;
}
}

namespace Two {
/// magic octet prefix for PROXY protocol version 2
inline const auto &
Magic()
{
    static const auto magic = new SBuf("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
    return *magic;
}
}

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_HEADER_H */

