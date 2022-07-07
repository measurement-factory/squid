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
    listenConn(),
    name_(nullptr),
    spec_(nullptr)
{
}

AnyP::PortCfg::~PortCfg()
{
    if (Comm::IsConnOpen(listenConn)) {
        listenConn->close();
        listenConn = NULL;
    }

    safe_free(spec_);
    safe_free(name_);
    safe_free(defaultsite);
}

AnyP::PortCfg::PortCfg(const PortCfg &other):
    next(), // special case; see assert() below
    s(other.s),
    transport(other.transport),
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
    secure(other.secure),
    name_(other.name_ ? xstrdup(other.name_) : nullptr),
    spec_(other.spec_ ? xstrdup(other.spec_) : nullptr)
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
    if (name_) {
        os << Debug::Extra << "listening port: " << name_;
    } else {
        assert(spec_);
        const auto scheme = AnyP::UriScheme(transport.protocol).image();
        os << Debug::Extra << "listening port specification: " << scheme << "_port " << spec_;
    }

    return os;
}

AnyP::PortCfgRange
HttpPorts()
{
    return AnyP::PortCfgRange(HttpPortList);
}

AnyP::PortCfgRange
FtpPorts()
{
    return AnyP::PortCfgRange(FtpPortList);
}

