/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/EnumIterator.h"
#include "proxyp/Elements.h"
#include "proxyp/Header.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "StrList.h"


ProxyProtocol::Header::Header(const SBuf &ver, const Two::Command cmd):
    version_(ver),
    command_(cmd),
    ignoreAddresses_(false)
{}

void
ProxyProtocol::Header::packInto(MemBuf &mb) const
{
    const uint8_t ver = (version_.cmp("1.0") == 0) ? 1 : 2;
    const SBuf magic = ver == 1 ? One::Magic() : Two::Magic();
    mb.append(magic.rawContent(), magic.length());
    uint8_t versionAndCommand = command_;
    versionAndCommand |= ver << 4;
    mb.append(reinterpret_cast<const char *>(&versionAndCommand), sizeof(versionAndCommand));

    const auto family = sourceAddress.isIPv4() ? Two::afInet : Two::afInet6;
    uint8_t addressAndFamily = Two::tpStream;
    addressAndFamily |= family << 4;
    mb.append(reinterpret_cast<const char *>(&addressAndFamily), sizeof(addressAndFamily));

    if (family == Two::afInet) {
        // https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt :
        // for TCP/UDP over IPv4, len = 12
        // for TCP/UDP over IPv6, len = 36
        const uint16_t len = 12;
        mb.append(reinterpret_cast<const char *>(&len), sizeof(len));
        struct in_addr src;
        sourceAddress.getInAddr(src);
        mb.append(reinterpret_cast<const char *>(&src), sizeof(src));
        struct in_addr dst;
        destinationAddress.getInAddr(dst);
        mb.append(reinterpret_cast<const char*>(&dst), sizeof(dst));
    } else {
        const uint16_t len = 36;
        mb.append(reinterpret_cast<const char *>(&len), sizeof(len));
        struct in6_addr host;
        sourceAddress.getInAddr(host);
        mb.append(reinterpret_cast<const char*>(&host), sizeof(host));
        struct in_addr dst;
        destinationAddress.getInAddr(dst);
        mb.append(reinterpret_cast<char*>(&dst), sizeof(dst));
    }
    const auto srcPort = htons(sourceAddress.port());
    mb.append(reinterpret_cast<const char *>(&srcPort), sizeof(srcPort));
    const auto dstPort = htons(destinationAddress.port());
    mb.append(reinterpret_cast<const char *>(&dstPort), sizeof(dstPort));
}

SBuf
ProxyProtocol::Header::toMime() const
{
    SBufStream result;
    for (const auto fieldType: EnumRange(Two::htPseudoBegin, Two::htPseudoEnd)) {
        const auto value = getValues(fieldType);
        if (!value.isEmpty())
            result << PseudoFieldTypeToFieldName(fieldType) << ": " << value << "\r\n";
    }
    // cannot reuse Header::getValues(): need the original TLVs layout
    for (const auto &tlv: tlvs)
        result << tlv.type << ": " << tlv.value << "\r\n";
    return result.buf();
}

SBuf
ProxyProtocol::Header::getValues(const uint32_t headerType, const char sep) const
{
    switch (headerType) {

    case Two::htPseudoVersion:
        return version_;

    case Two::htPseudoCommand:
        return ToSBuf(command_);

    case Two::htPseudoSrcAddr: {
        if (!hasAddresses())
            return SBuf();
        auto logAddr = sourceAddress;
        logAddr.applyClientMask(Config.Addrs.client_netmask);
        char ipBuf[MAX_IPSTRLEN];
        return SBuf(logAddr.toStr(ipBuf, sizeof(ipBuf)));
    }

    case Two::htPseudoDstAddr: {
        if (!hasAddresses())
            return SBuf();
        char ipBuf[MAX_IPSTRLEN];
        return SBuf(destinationAddress.toStr(ipBuf, sizeof(ipBuf)));
    }

    case Two::htPseudoSrcPort: {
        return hasAddresses() ? ToSBuf(sourceAddress.port()) : SBuf();
    }

    case Two::htPseudoDstPort: {
        return hasAddresses() ? ToSBuf(destinationAddress.port()) : SBuf();
    }

    default: {
        SBufStream result;
        for (const auto &m: tlvs) {
            if (m.type == headerType) {
                // XXX: result.tellp() always returns -1
                if (!result.buf().isEmpty())
                    result << sep;
                result << m.value;
            }
        }
        return result.buf();
    }
    }
}

SBuf
ProxyProtocol::Header::getElem(const uint32_t headerType, const char *member, const char sep) const
{
    const auto whole = SBufToString(getValues(headerType, sep));
    return getListMember(whole, member, sep);
}

const SBuf &
ProxyProtocol::Header::addressFamily() const
{
    static const SBuf v4("4");
    static const SBuf v6("6");
    static const SBuf vMix("mix");
    return
        (sourceAddress.isIPv6() && destinationAddress.isIPv6()) ? v6 :
        (sourceAddress.isIPv4() && destinationAddress.isIPv4()) ? v4 :
        vMix;
}

