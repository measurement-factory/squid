/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

    // TODO: Removal is also currently unsupported. Detect/reject it as well.
    if (!currentCfg)
        throw TextException("no support for adding a new or changing an existing listening port address", Here());

    // TODO: Consider reporting unchanged configurations.
    currentCfg->update(newCfg);
}

