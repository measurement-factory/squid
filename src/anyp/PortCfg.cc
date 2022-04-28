/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "anyp/UriScheme.h"
#include "comm.h"
#include "fatal.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"
#include "security/PeerOptions.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <limits>

AnyP::PortCfgPointer HttpPortList;
AnyP::PortCfgPointer FtpPortList;

int NHttpSockets = 0;
int HttpSockets[MAXTCPLISTENPORTS];

AnyP::PortCfg::PortCfg(const TrafficModeFlags::PortKind aPortKind):
    next(),
    s(),
    transport(AnyP::PROTO_HTTP,1,1), // "Squid is an HTTP proxy", etc.
    name(NULL),
    defaultsite(NULL),
    flags(aPortKind),
    allow_direct(false),
    vhost(false),
    actAsOrigin(false),
    ignore_cc(false),
    connection_auth_disabled(false),
    ftp_track_dirs(false),
    vport(0),
    disable_pmtu_discovery(0),
    workerQueues(false),
    listenConn()
{
}

AnyP::PortCfg::~PortCfg()
{
    if (Comm::IsConnOpen(listenConn)) {
        listenConn->close();
        listenConn = NULL;
    }

    safe_free(name);
    safe_free(defaultsite);
}

AnyP::PortCfg::PortCfg(const PortCfg &other):
    next(), // special case; see assert() below
    s(other.s),
    transport(other.transport),
    name(other.name ? xstrdup(other.name) : nullptr),
    defaultsite(other.defaultsite ? xstrdup(other.defaultsite) : nullptr),
    flags(other.flags),
    allow_direct(other.allow_direct),
    vhost(other.vhost),
    actAsOrigin(other.actAsOrigin),
    ignore_cc(other.ignore_cc),
    connection_auth_disabled(other.connection_auth_disabled),
    ftp_track_dirs(other.ftp_track_dirs),
    vport(other.vport),
    disable_pmtu_discovery(other.disable_pmtu_discovery),
    workerQueues(other.workerQueues),
    tcp_keepalive(other.tcp_keepalive),
    listenConn(), // special case; see assert() below
    secure(other.secure)
{
    // to simplify, we only support port copying during parsing
    assert(!other.next);
    assert(!other.listenConn);
}

AnyP::PortCfg *
AnyP::PortCfg::ipV4clone() const
{
    const auto clone = new PortCfg(*this);
    clone->s.setIPv4();
    debugs(3, 3, AnyP::UriScheme(transport.protocol).image() << "_port: " <<
           "cloned wildcard address for split-stack: " << s << " and " << clone->s);
    return clone;
}

ScopedId
AnyP::PortCfg::codeContextGist() const
{
    // Unfortunately, .name lifetime is too short in FTP use cases.
    // TODO: Consider adding InstanceId<uint32_t> to all RefCountable classes.
    return ScopedId("port");
}

std::ostream &
AnyP::PortCfg::detailCodeContext(std::ostream &os) const
{
    // parsePortSpecification() defaults optional port name to the required
    // listening address so we cannot easily distinguish one from the other.
    if (name)
        os << Debug::Extra << "listening port: " << name;
    else if (s.port())
        os << Debug::Extra << "listening port address: " << s;
    return os;
}

typedef std::map<AnyP::TrafficModeFlags::PortKind, const char *> PortKindMap;
static const PortKindMap PortKindStrings =
{
    {AnyP::TrafficModeFlags::httpPort, "http_port"},
    {AnyP::TrafficModeFlags::httpsPort, "https_port"},
    {AnyP::TrafficModeFlags::ftpPort, "ftp_port"}
};

static const char *
PortOption(const AnyP::TrafficModeFlags::Pointer flagPointer)
{
    typedef std::pair<AnyP::TrafficModeFlags::Pointer, const char *> PortOptionPair;
    static constexpr std::array<PortOptionPair, 5> PortOptionStrings = { {
            {&AnyP::TrafficModeFlags::accelSurrogate, "accel"},
            {&AnyP::TrafficModeFlags::proxySurrogate, "require-proxy-header"},
            {&AnyP::TrafficModeFlags::natIntercept, "intercept"},
            {&AnyP::TrafficModeFlags::tproxyIntercept, "tproxy"},
            {&AnyP::TrafficModeFlags::tunnelSslBumping, "ssl-bump"}
        }
    };

    const auto found = std::find_if(PortOptionStrings.begin(), PortOptionStrings.end(),
            [&flagPointer](const PortOptionPair &p) { return p.first == flagPointer; });
    assert(found != PortOptionStrings.end());
    return found->second;
}

std::ostream &
AnyP::operator <<(std::ostream &os, const TrafficModeFlags::Pointer flagPointer)
{
    os << PortOption(flagPointer);
    return os;
}

std::ostream &
AnyP::operator <<(std::ostream &os, const TrafficModeFlags::List &list)
{
    SBuf str;
    for (const auto &p: list) {
        if (!str.isEmpty())
            str.append(',');
        str.append(PortOption(p));
    }
    os << str;
    return os;
}

void
AnyP::PortCfg::rejectFlags(const AnyP::TrafficModeFlags::List &list)
{
    assert(list.size());

    const auto &rawFlags = flags.rawConfig();
    for (const auto &p: list) {
        if (rawFlags.*p)
            throw TextException(ToSBuf(p, " is unsupported on ", PortKindStrings.at(rawFlags.portKind)), Here());
    }
}

void
AnyP::PortCfg::allowEither(const AnyP::TrafficModeFlags::List &list)
{
    assert(list.size());

    const auto &rawFlags = flags.rawConfig();
    if (std::count_if(list.begin(), list.end(),
    [&rawFlags](const AnyP::TrafficModeFlags::Pointer p) { return rawFlags.*p; }) > 1) {
        throw TextException(ToSBuf("the combination of ", list, " is unsupported on ",
                    PortKindStrings.at(rawFlags.portKind)), Here());
    }
}

void
AnyP::PortCfg::checkImplication(const AnyP::TrafficModeFlags::List &list1, const AnyP::TrafficModeFlags::List &list2)
{
    assert(list1.size());
    assert(list2.size());

    const auto &rawFlags = flags.rawConfig();
    if (std::find_if(list1.begin(), list1.end(),
    [&rawFlags](const AnyP::TrafficModeFlags::Pointer p) { return rawFlags.*p; }) == list1.end())
        return;

    if (std::find_if(list2.begin(), list2.end(),
    [&rawFlags](const AnyP::TrafficModeFlags::Pointer p) { return rawFlags.*p; }) != list2.end())
        return;

    const auto detail1 = (list1.size() == 1) ? "" : "any of ";
    const auto detail2 = (list2.size() == 1) ? "" : "one of ";

    throw TextException(ToSBuf(detail1, list1, " requires ", detail2, list2,
                " on ", PortKindStrings.at(rawFlags.portKind)), Here());
}

void
AnyP::PortCfg::checkFlags()
{
    using Flags = AnyP::TrafficModeFlags;
    const auto &rawFlags = flags.rawConfig();

    switch (rawFlags.portKind) {

    case Flags::httpPort: {
        allowEither({&TrafficModeFlags::accelSurrogate, &TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept});
    }
    break;

    case Flags::httpsPort: {
        allowEither({&TrafficModeFlags::accelSurrogate, &TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogate});
        checkImplication({&TrafficModeFlags::tunnelSslBumping},
                {&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogate});
        checkImplication({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogate},
                {&TrafficModeFlags::tunnelSslBumping});
    }
    break;

    case Flags::ftpPort: {
        allowEither({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept});
        rejectFlags({&TrafficModeFlags::accelSurrogate, &TrafficModeFlags::proxySurrogate, &TrafficModeFlags::tunnelSslBumping});
    }
    break;

    default:
        fatal("invalid PortKind");
    }

    if (rawFlags.tproxyIntercept && rawFlags.proxySurrogate) {
        // receiving is still permitted, so we do not unset the TPROXY flag
        // spoofing access control override takes care of the spoof disable later
        debugs(3, DBG_IMPORTANT, "Disabling TPROXY Spoofing on port " << s << " (require-proxy-header enabled)");
    }
}

