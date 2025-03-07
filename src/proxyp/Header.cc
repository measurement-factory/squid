/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/EnumIterator.h"
#include "parser/BinaryPacker.h"
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
ProxyProtocol::Header::pack(BinaryPacker &pack) const
{
    pack.area("magic", Two::Magic());

    const auto ver = 2; // XXX: We should be using version_, but version_ should use int instead of SBuf!
    Assure(ver == 2); // no support for serializing using legacy v1 format
    pack.uint8("version and command", (ver << 4) | command_);

    BinaryPacker tail;

    if (command_ == Two::cmdLocal) {
        // PROXY protocol tells us to send (and receiver to discard) this zero.
        pack.uint8("LOCAL protocol block", 0);
    } else {
        Assure(sourceAddress.isIPv4() == destinationAddress.isIPv4()); // one family for both addresses
        const auto family = sourceAddress.isIPv4() ? Two::afInet : Two::afInet6;
        pack.uint8("socket family and transport protocol", (family << 4) | Two::tpStream);

        tail.inet("src_addr", sourceAddress);
        tail.inet("dst_addr", destinationAddress);
        tail.uint16("src_port", sourceAddress.port());
        tail.uint16("dst_port", destinationAddress.port());
    }

    for (const auto &tlv: tlvs) {
        tail.uint8("pp2_tlv::type", tlv.type);
        tail.pstring16("pp2_tlv::value", tlv.value);
    }

    // Optimization TODO: This copy can be removed by packing length placeholder
    // and std::moving BinaryPacker::output_ from `pack` into `tail` and back.
    pack.pstring16("addresses and TLVs", tail.packed());
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

