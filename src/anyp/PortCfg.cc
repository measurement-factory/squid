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
#include "security/PeerOptions.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <cstring>
#include <limits>

AnyP::PortCfgPointer HttpPortList;
AnyP::PortCfgPointer FtpPortList;

int NHttpSockets = 0;
int HttpSockets[MAXTCPLISTENPORTS];

AnyP::PortCfg::PortCfg() :
    next(),
    s(),
    transport(AnyP::PROTO_HTTP,1,1), // "Squid is an HTTP proxy", etc.
    name(NULL),
    defaultsite(NULL),
    flags(),
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
    AnyP::PortCfgPointer b = new AnyP::PortCfg();
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

typedef std::pair<AnyP::TrafficModeFlags::Flags, const char *> PortOptionPair;
constexpr std::array<PortOptionPair, 5> PortOptionStrings =
{
    {
        {AnyP::TrafficModeFlags::accelSurrogate, "accel"},
        {AnyP::TrafficModeFlags::proxySurrogateHttp, "require-proxy-header"},
        {AnyP::TrafficModeFlags::natIntercept, "intercept"},
        {AnyP::TrafficModeFlags::tproxyIntercept, "tproxy"},
        {AnyP::TrafficModeFlags::tunnelSslBumping, "ssl-bump"}
    }
};

typedef std::pair<AnyP::TrafficModeFlags::PortKind, const char *> PortKindPair;
constexpr std::array<PortKindPair, 3> PortKindStrings =
{
    {
        {AnyP::TrafficModeFlags::httpPort, "http_port"},
        {AnyP::TrafficModeFlags::httpsPort, "https_port"},
        {AnyP::TrafficModeFlags::ftpPort, "ftp_port"},
    }
};

static SBuf
PortOptionString(const AnyP::TrafficModeFlags &flags)
{
    SBuf str;
    for (const auto &p: PortOptionStrings) {
        if (flags.has(p.first)) {
            if (!str.isEmpty())
                str.append(',');
            str.append(p.second);
        }
    }
    assert(!str.isEmpty());
    return str;
}

static const char *
PortKindString(const AnyP::TrafficModeFlags &flags)
{
    for (const auto &p: PortKindStrings)
        if (p.first == flags.portKind)
            return p.second;
    assert(false); // unreachable
    return nullptr;
}

void
AnyP::PortCfg::rejectFlags(const uint64_t otherFlags, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    const TrafficModeFlags other(otherFlags, rawFlags.portKind);
    for (const auto &p: PortOptionStrings) {
        if (rawFlags.has(p.first) && other.has(p.first)) {
            debugs(3, DBG_CRITICAL, "FATAL: " << p.second << " is unsupported on " << PortKindString(rawFlags) <<  ' ' << detail);
            self_destruct();
        }
    }
}

void
AnyP::PortCfg::allowEither(const uint64_t otherFlags, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    if (rawFlags.commonMoreThanOne(otherFlags)) {
        const TrafficModeFlags other(otherFlags, rawFlags.portKind);
        debugs(3, DBG_CRITICAL, "FATAL: the combination of " << PortOptionString(other) <<
                " is unsupported on " << PortKindString(rawFlags) << ' ' << detail);
        self_destruct();
    }
}

void
AnyP::PortCfg::requireEither(const uint64_t otherFlags, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    if (rawFlags.commonMoreThanOne(otherFlags)) {
        const TrafficModeFlags other(otherFlags, rawFlags.portKind);
        debugs(3, DBG_CRITICAL, "FATAL: exactly one of " << PortOptionString(other) <<
                " is required on " << PortKindString(rawFlags) << ' ' << detail);
        self_destruct();
    }
}

void
AnyP::PortCfg::requireAll(const uint64_t otherFlags, const char *detail)
{
    if (!flags.rawConfig().hasAll(otherFlags)) {
        const auto &rawFlags = flags.rawConfig();
        const TrafficModeFlags other(otherFlags, rawFlags.portKind);
        debugs(3, DBG_CRITICAL, "FATAL: " << PortOptionString(other) << " is required on "
                << PortKindString(rawFlags) << ' ' << detail);
        self_destruct();
    }
}

