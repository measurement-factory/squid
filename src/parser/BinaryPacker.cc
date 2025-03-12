/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ip/Address.h"
#include "parser/BinaryPacker.h"

#include <limits>

/// helper for methods that need to store a single byte
void
BinaryPacker::packOctet_(const uint8_t value)
{
    output_.append(static_cast<char>(value));
}

/// helper for methods that need to store a variable number of bytes
void
BinaryPacker::packOctets_(const void *value, const size_t size)
{
    output_.append(static_cast<const char*>(value), size);
}

/// helper for reporting to-be-serialized field
template <typename Value>
void
BinaryPacker::packing_(const char * const description, const Value &value, const size_t size) const
{
    debugs(24, 7, description << "[" << size << " bytes]: " << value);
}

void
BinaryPacker::uint8(const char * const description, const uint8_t value)
{
    packing_(description, value, 1);
    packOctet_(value);
}

void
BinaryPacker::uint16(const char * const description, const uint16_t value)
{
    packing_(description, value, 2);
    packOctet_(value >> 8);
    packOctet_(value);
}

void
BinaryPacker::area(const char * const description, const SBuf &blob)
{
    packing_(description, __FUNCTION__, blob.length());
    packOctets_(blob.rawContent(), blob.length());
}

void
BinaryPacker::inet(const char * const description, const Ip::Address &ip)
{
    if (ip.isIPv4()) {
        in_addr ip4;
        packing_(description, ip, sizeof(ip4));
        ip.getInAddr(ip4);
        packOctets_(&ip4, sizeof(ip4));
    } else {
        in6_addr ip6;
        packing_(description, ip, sizeof(ip6));
        ip.getInAddr(ip6);
        packOctets_(&ip6, sizeof(ip6));
    }
}

void
BinaryPacker::pstring8(const char * const description, const SBuf &area)
{
    packing_(description, __FUNCTION__, area.length());
    Assure(area.length() <= std::numeric_limits<uint8_t>::max());
    uint8("pstring8() length", area.length());
    packOctets_(area.rawContent(), area.length());
}

void
BinaryPacker::pstring16(const char * const description, const SBuf &area)
{
    packing_(description, __FUNCTION__, area.length());
    Assure(area.length() <= std::numeric_limits<uint16_t>::max());
    uint16("pstring16() length", area.length());
    packOctets_(area.rawContent(), area.length());
}
