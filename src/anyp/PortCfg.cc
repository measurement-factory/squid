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

typedef std::pair<AnyP::TrafficModeFlags::Pointer, const char *> PortOptionPair;
constexpr std::array<PortOptionPair, 5> PortOptionStrings =
{
    {
        {&AnyP::TrafficModeFlags::accelSurrogate, "accel"},
        {&AnyP::TrafficModeFlags::proxySurrogateHttp, "require-proxy-header"},
        {&AnyP::TrafficModeFlags::natIntercept, "intercept"},
        {&AnyP::TrafficModeFlags::tproxyIntercept, "tproxy"},
        {&AnyP::TrafficModeFlags::tunnelSslBumping, "ssl-bump"}
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

static const char *
PortOptionStr(const AnyP::TrafficModeFlags::Pointer flagPointer)
{
    for (const auto &p: PortOptionStrings) {
        if (p.first == flagPointer)
           return p.second;
    }
    assert(false); // unreachable
    return nullptr;
}

static SBuf
PortOptionStrList(const AnyP::TrafficModeFlags::List &list)
{
    SBuf str;
    for (const auto &p: list) {
        if (!str.isEmpty())
            str.append(',');
        str.append(PortOptionStr(p));
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
AnyP::PortCfg::rejectFlags(const AnyP::TrafficModeFlags::List &list, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    for (const auto &p: list) {
        if (rawFlags.*p) {
            debugs(3, DBG_CRITICAL, "FATAL: " << PortOptionStr(p) << " is unsupported on " << PortKindString(rawFlags) <<  ' ' << detail);
            self_destruct();
        }
    }
}

void
AnyP::PortCfg::allowEither(const AnyP::TrafficModeFlags::List &list, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    int flagsCount = 0;
    for (const auto &p: list) {
        if (rawFlags.*p)
            flagsCount++;
    }
    if (flagsCount <= 1)
        return;

    debugs(3, DBG_CRITICAL, "FATAL: the combination of " << PortOptionStrList(list) <<
            " is unsupported on " << PortKindString(rawFlags) << ' ' << detail);
    self_destruct();
}

void
AnyP::PortCfg::requireEither(const AnyP::TrafficModeFlags::List &list, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    int flagsCount = 0;
    for (const auto &p: list) {
        if (rawFlags.*p)
            flagsCount++;
    }
    if (flagsCount == 1)
        return;

    debugs(3, DBG_CRITICAL, "FATAL: exactly one of " << PortOptionStrList(list) <<
            " is required on " << PortKindString(rawFlags) << ' ' << detail);
    self_destruct();
}

void
AnyP::PortCfg::checkImplication(const AnyP::TrafficModeFlags::Pointer aFlag, const AnyP::TrafficModeFlags::List &list, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    if (!(rawFlags.*aFlag))
        return;
    int flagsCount = 0;
    for (const auto &p: list) {
        if (rawFlags.*p)
            flagsCount++;
    }
    if (!flagsCount)
        debugs(3, DBG_CRITICAL, "FATAL: " << PortOptionStr(aFlag) << " requires one of " << PortOptionStrList(list) <<
                " on " << PortKindString(rawFlags) << ' ' << detail);
}

void
AnyP::PortCfg::checkImplication(const AnyP::TrafficModeFlags::Pointer aFlag, const AnyP::TrafficModeFlags::Pointer otherFlag, const char *detail)
{
    const auto &rawFlags = flags.rawConfig();
    if (!(rawFlags.*aFlag))
        return;
    if (!(rawFlags.*otherFlag))
        debugs(3, DBG_CRITICAL, "FATAL: " << PortOptionStr(aFlag) << " requires " << PortOptionStr(otherFlag) <<
                " on " << PortKindString(rawFlags) << ' ' << detail);
}

bool
AnyP::PortCfg::hasAll(const AnyP::TrafficModeFlags::List &list)
{
    const auto &rawFlags = flags.rawConfig();
    for (const auto &p: list) {
        if (!(rawFlags.*p))
            return false;
    }
    return true;
}

void
AnyP::PortCfg::requireAll(const AnyP::TrafficModeFlags::List &list, const char *detail)
{
    if (!hasAll(list)) {
        const auto &rawFlags = flags.rawConfig();
        debugs(3, DBG_CRITICAL, "FATAL: all of " << PortOptionStrList(list) << " required on "
                << PortKindString(rawFlags) << ' ' << detail);
        self_destruct();
    }
}

void
AnyP::PortCfg::checkFlags()
{
    using Flags = AnyP::TrafficModeFlags;
    const auto &rawFlags = flags.rawConfig();

    switch (rawFlags.portKind) {

    case Flags::httpPort: {
        if (rawFlags.accelSurrogate)
            rejectFlags({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept}, "accel");
        else
            allowEither({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept});
    }
    break;

    case Flags::httpsPort: {
        if (rawFlags.accelSurrogate) {
            rejectFlags({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept,
                    &TrafficModeFlags::proxySurrogateHttp, &TrafficModeFlags::tunnelSslBumping}, "accel");
        } else {
            checkImplication(&TrafficModeFlags::tunnelSslBumping,
                    {&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogateHttp});
            checkImplication(&TrafficModeFlags::natIntercept, &TrafficModeFlags::tunnelSslBumping);
            checkImplication(&TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::tunnelSslBumping);
            checkImplication(&TrafficModeFlags::proxySurrogateHttp, &TrafficModeFlags::tunnelSslBumping);
            allowEither({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogateHttp});
        }
    }
    break;

    case Flags::ftpPort:
        rejectFlags({&TrafficModeFlags::accelSurrogate, &TrafficModeFlags::proxySurrogateHttp, &TrafficModeFlags::tunnelSslBumping});
        allowEither({&TrafficModeFlags::natIntercept, &TrafficModeFlags::tproxyIntercept});
        break;

    default:
        fatal("unreachable");
    }

    if (hasAll({&TrafficModeFlags::tproxyIntercept, &TrafficModeFlags::proxySurrogateHttp})) {
        // receiving is still permitted, so we do not unset the TPROXY flag
        // spoofing access control override takes care of the spoof disable later
        debugs(3, DBG_IMPORTANT, "Disabling TPROXY Spoofing on port " << s << " (require-proxy-header enabled)");
    }
}

