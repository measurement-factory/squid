/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "cache_cf.h"
#include "comm.h"
#include "Debug.h"
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

AnyP::PortCfg::PortCfg(const AnyP::TrafficModeFlags::PortKind aPortKind) :
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
    memset(&tcp_keepalive, 0, sizeof(tcp_keepalive));
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

AnyP::PortCfgPointer
AnyP::PortCfg::clone() const
{
    AnyP::PortCfgPointer b = new AnyP::PortCfg(flags.rawConfig().portKind);
    b->s = s;
    if (name)
        b->name = xstrdup(name);
    if (defaultsite)
        b->defaultsite = xstrdup(defaultsite);

    b->transport = transport;
    b->flags = flags;
    b->allow_direct = allow_direct;
    b->vhost = vhost;
    b->vport = vport;
    b->connection_auth_disabled = connection_auth_disabled;
    b->workerQueues = workerQueues;
    b->ftp_track_dirs = ftp_track_dirs;
    b->disable_pmtu_discovery = disable_pmtu_discovery;
    b->tcp_keepalive = tcp_keepalive;
    b->secure = secure;

    return b;
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
PortOptionStr(const AnyP::TrafficModeFlags::Pointer flagPointer)
{
    typedef std::pair<AnyP::TrafficModeFlags::Pointer, const char *> PortOptionPair;
    static constexpr std::array<PortOptionPair, 5> PortOptionStrings = { {
            {&AnyP::TrafficModeFlags::accelSurrogate, "accel"},
            {&AnyP::TrafficModeFlags::proxySurrogateHttp, "require-proxy-header"},
            {&AnyP::TrafficModeFlags::natIntercept, "intercept"},
            {&AnyP::TrafficModeFlags::tproxyIntercept, "tproxy"},
            {&AnyP::TrafficModeFlags::tunnelSslBumping, "ssl-bump"}
        }
    };

    for (const auto &p: PortOptionStrings) {
        if (p.first == flagPointer)
           return p.second;
    }
    assert(false); // unreachable
    return nullptr;
}

std::ostream &
operator <<(std::ostream &os, const AnyP::TrafficModeFlags::Pointer flagPointer)
{
    return os << PortOptionStr(flagPointer);
}

std::ostream &
operator <<(std::ostream &os, const AnyP::TrafficModeFlags::List &list)
{
    SBuf str;
    for (const auto &p: list) {
        if (!str.isEmpty())
            str.append(',');
        str.append(PortOptionStr(p));
    }
    assert(!str.isEmpty());
    return os << str;
}

void
AnyP::PortCfg::rejectFlags(const AnyP::TrafficModeFlags::List &list)
{
    const auto &rawFlags = flags.rawConfig();
    for (const auto &p: list) {
        if (rawFlags.*p)
            throw TextException(ToSBuf(p, " is unsupported on ", PortKindStrings.at(rawFlags.portKind)), Here());
    }
}

void
AnyP::PortCfg::allowEither(const AnyP::TrafficModeFlags::List &list)
{
    const auto &rawFlags = flags.rawConfig();

    if (std::count_if(list.begin(), list.end(),
    [&rawFlags](const AnyP::TrafficModeFlags::Pointer p) { return rawFlags.*p; }) > 1) {
        throw TextException(ToSBuf("the combination of ", list, " is unsupported on ",
                    PortKindStrings.at(rawFlags.portKind)), Here());
    }
}

void
AnyP::PortCfg::checkFlagImplication(const AnyP::TrafficModeFlags::Pointer aFlag, const AnyP::TrafficModeFlags::List &list)
{
    assert(list.size());

    const auto &rawFlags = flags.rawConfig();

    if (!(rawFlags.*aFlag))
        return;

    if (std::find_if(list.begin(), list.end(),
    [&rawFlags](const AnyP::TrafficModeFlags::Pointer p) { return rawFlags.*p; }) != list.end())
        return;

    const auto detail = (list.size() == 1) ? "" : "one of ";
    throw TextException(ToSBuf(aFlag, " requires ", detail, list,
                " on ", PortKindStrings.at(rawFlags.portKind)), Here());
}

void
AnyP::PortCfg::checkListImplication(const AnyP::TrafficModeFlags::List &list, const AnyP::TrafficModeFlags::Pointer aFlag)
{
    assert(list.size());

    const auto &rawFlags = flags.rawConfig();

    if (std::find_if(list.begin(), list.end(),
    [&rawFlags](const AnyP::TrafficModeFlags::Pointer p) { return rawFlags.*p; }) == list.end())
        return;

    if (rawFlags.*aFlag)
        return;

    const auto detail = (list.size() == 1) ? "" : "any of ";
    throw TextException(ToSBuf(detail, list, " requires ", aFlag,
                " on ", PortKindStrings.at(rawFlags.portKind)), Here());
}

void
AnyP::PortCfg::checkFlags()
{
    using Flags = AnyP::TrafficModeFlags;
    const auto &rawFlags = flags.rawConfig();

    switch (rawFlags.portKind) {

    case Flags::httpPort:
        allowEither({&TrafficModeFlags::accelSurrogate, &TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept});
        break;

    case Flags::httpsPort: {
        allowEither({&TrafficModeFlags::accelSurrogate, &TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogateHttp});

        checkFlagImplication(&TrafficModeFlags::tunnelSslBumping,
                {&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogateHttp});
        checkListImplication({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogateHttp},
                &TrafficModeFlags::tunnelSslBumping);
    }
    break;

    case Flags::ftpPort:
        rejectFlags({&TrafficModeFlags::accelSurrogate, &TrafficModeFlags::proxySurrogateHttp, &TrafficModeFlags::tunnelSslBumping});
        allowEither({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept});
        break;

    default:
        fatal("unreachable");
    }

    if (rawFlags.tproxyIntercept && rawFlags.proxySurrogateHttp) {
        // receiving is still permitted, so we do not unset the TPROXY flag
        // spoofing access control override takes care of the spoof disable later
        debugs(3, DBG_IMPORTANT, "Disabling TPROXY Spoofing on port " << s << " (require-proxy-header enabled)");
    }
}

