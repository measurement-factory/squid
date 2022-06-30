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
#include "base/TextException.h"
#include "comm.h"
#include "fatal.h"
#include "ftp/Elements.h"
#include "http/ProtocolVersion.h"
#include "sbuf/Stream.h"
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

static AnyP::TrafficModeFlags::PortKind
ParseDirective(const SBuf &directive)
{
    if (directive.cmp("http_port") == 0)
        return AnyP::TrafficModeFlags::httpPort;
    else if (directive.cmp("https_port") == 0)
        return AnyP::TrafficModeFlags::httpsPort;
    else {
        assert(directive.cmp("ftp_port") == 0);
        return AnyP::TrafficModeFlags::ftpPort;
    }
}

static AnyP::ProtocolVersion
DefaultProtocol(const SBuf &directive)
{
    if (directive.cmp("http_port") == 0)
        return Http::ProtocolVersion(1,1);
    else if (directive.cmp("https_port") == 0)
        return AnyP::ProtocolVersion(AnyP::PROTO_HTTPS, 1,1);
    else {
        assert(directive.cmp("ftp_port") == 0);
        return Ftp::ProtocolVersion();
    }
}

AnyP::PortCfg::PortCfg(const SBuf &directive):
    next(),
    s(),
    directiveName(directive),
    transport(DefaultProtocol(directive)), // "Squid is an HTTP proxy", etc.
    name(NULL),
    defaultsite(NULL),
    flags(ParseDirective(directiveName)),
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
    debugs(3, 3, directiveName << " cloned wildcard address for split-stack: " << s << " and " << clone->s);
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
    os << Debug::Extra << "listening port: " << *this;
    return os;
}

void
AnyP::PortCfg::print(std::ostream &os) const
{
    os << directiveName << ' ';
    // parsePortSpecification() defaults optional port name to the required
    // listening address so we cannot easily distinguish one from the other.
    if (name)
        os << name;
    else
        os << s;
}

