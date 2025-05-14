/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "anyp/UriScheme.h"
#include "comm.h"
#include "enums.h"
#include "fatal.h"
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
    name(nullptr),
    defaultsite(nullptr),
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
    stale(false),
    listenConn()
{
}

AnyP::PortCfg::~PortCfg()
{
    if (Comm::IsConnOpen(listenConn)) {
        listenConn->close();
        listenConn = nullptr;
    }

    safe_free(name);
    safe_free(defaultsite);
}

// Keep in sync with AnyP::PortCfg::update().
/// Construct a clone of a given PortCfg object but with a given custom address
AnyP::PortCfg::PortCfg(const PortCfg &other, const Ip::Address &ipV4cloneAddrress):
    next(), // special case; see assert() below
    s(ipV4cloneAddrress), // instead of other.s
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
    stale(other.stale),
    tcp_keepalive(other.tcp_keepalive),
    listenConn(), // special case; see assert() below
    secure(other.secure)
{
    // to simplify, we only support port copying during parsing
    assert(!other.next);
    assert(!other.listenConn);
}

void
AnyP::PortCfg::update(const PortCfg &other)
{
    debugs(3, 7, *this);

    // Keep in sync with cloning code (including fields order). Fields commented
    // out below must be preserved during reconfiguration updates.

    // preserve next
    // preserve s

    transport = other.transport;

    safe_free(name);
    name = other.name ? xstrdup(other.name) : nullptr;

    safe_free(defaultsite);
    defaultsite = other.defaultsite ? xstrdup(other.defaultsite) : nullptr;

    // keep in sync with clientStartListeningOn()
    if (flags.tproxyIntercept != other.flags.tproxyIntercept)
        throw TextException("no support for changing 'tproxy' setting of a listening port", Here());
    if (flags.natIntercept != other.flags.natIntercept)
        throw TextException("no support for changing 'transparent' or 'intercept' setting of a listening port", Here());
    flags = other.flags;

    allow_direct = other.allow_direct;
    vhost = other.vhost;
    actAsOrigin = other.actAsOrigin;
    ignore_cc = other.ignore_cc;
    connection_auth_disabled = other.connection_auth_disabled;
    ftp_track_dirs = other.ftp_track_dirs;
    vport = other.vport;
    disable_pmtu_discovery = other.disable_pmtu_discovery;

    // keep in sync with clientStartListeningOn()
    if (workerQueues != other.workerQueues)
        throw TextException("no support for changing 'worker-queues' setting of a listening port", Here());
    workerQueues = other.workerQueues;

    stale = other.stale;
    Assure(!stale); // update() should be given fresh configurations

    tcp_keepalive = other.tcp_keepalive;

    // preserve listenConn

    secure = other.secure;
}

AnyP::PortCfg *
AnyP::PortCfg::ipV4clone() const
{
    auto otherAddress = s;
    otherAddress.setIPv4();
    const auto clone = new PortCfg(*this, otherAddress);
    debugs(3, 3, AnyP::UriScheme(transport.protocol).image() << "_port: " <<
           "cloned wildcard address for split-stack: " << s << " and " << clone->s);
    return clone;
}

void
AnyP::PortCfg::dump(std::ostream &os, const char * const directiveName) const
{
    os << directiveName << ' ' << s;

    // MODES and specific sub-options.
    if (flags.natIntercept)
        os << " intercept";

    else if (flags.tproxyIntercept)
        os << " tproxy";

    else if (flags.proxySurrogate)
        os << " require-proxy-header";

    else if (flags.accelSurrogate) {
        os << " accel";

        if (vhost)
            os << " vhost";

        if (vport < 0)
            os << " vport";
        else if (vport > 0)
            os << " vport=" << vport;

        if (defaultsite)
            os << " defaultsite=" << defaultsite;

        // TODO: compare against prefix of 'n' instead of assuming http_port
        if (transport.protocol != AnyP::PROTO_HTTP)
            os << " protocol=" << AnyP::ProtocolType_str[transport.protocol];

        if (allow_direct)
            os << " allow-direct";

        if (ignore_cc)
            os << " ignore-cc";
    }

    // Generic independent options

    if (name)
        os << " name=" << name;

#if USE_HTTP_VIOLATIONS
    if (!flags.accelSurrogate && ignore_cc)
        os << " ignore-cc";
#endif

    if (connection_auth_disabled)
        os << " connection-auth=off";
    else
        os << " connection-auth=on";

    if (disable_pmtu_discovery != DISABLE_PMTU_OFF) {
        const auto pmtu = (disable_pmtu_discovery == DISABLE_PMTU_ALWAYS) ? "always" : "transparent";
        os << " disable-pmtu-discovery=" << pmtu;
    }

    if (s.isAnyAddr() && !s.isIPv6())
        os << " ipv4";

    if (tcp_keepalive.enabled) {
        if (tcp_keepalive.idle || tcp_keepalive.interval || tcp_keepalive.timeout)
            os << " tcpkeepalive=" << tcp_keepalive.idle << ',' << tcp_keepalive.interval << ',' << tcp_keepalive.timeout;
        else
            os << " tcpkeepalive";
    }

#if USE_OPENSSL
    if (flags.tunnelSslBumping)
        os << " ssl-bump";
#endif

    secure.dumpCfg(os, "tls-");

    os << '\n';
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

std::ostream &
AnyP::operator <<(std::ostream &os, const PortCfg &cfg)
{
    // See AnyP::PortCfg::codeContextGist() and detailCodeContext() for caveats.
    os << "listening_port@";
    if (cfg.name)
        os << cfg.name;
    else if (cfg.s.port())
        os << cfg.s;
    else
        os << &cfg;
    return os;
}

void
UpdatePortCfg(const AnyP::PortCfgPointer &list, const AnyP::PortCfg &newCfg)
{
    debugs(3, 5, newCfg);
    AnyP::PortCfgPointer currentCfg; // to be determined
    for (auto cfg = list; cfg; cfg = cfg->next) {
        debugs(3, 7, "considering: " << *cfg);
        // Check PortCfg::s because that is the address Squid listens on and
        // because parsePortSpecification() computes it from sources that may
        // change even when the directive line stays unchanged (e.g.,
        // getaddrinfo(3) and FQDN lookups of http_port host:port address)
        if (cfg->s.compareWhole(newCfg.s) != 0)
            continue;
        Assure(!currentCfg); // we do not accept clashing port configurations
        currentCfg = cfg;
    }

    if (!currentCfg)
        throw TextException("no support for adding a new or changing an existing listening port address", Here());

    if (!currentCfg->stale)
        throw TextException("listening port is specified twice", Here());

    // TODO: Consider reporting unchanged configurations.
    currentCfg->update(newCfg);
}

