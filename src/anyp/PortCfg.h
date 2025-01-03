/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ANYP_PORTCFG_H
#define SQUID_SRC_ANYP_PORTCFG_H

#include "anyp/forward.h"
#include "anyp/ProtocolVersion.h"
#include "anyp/TrafficMode.h"
#include "base/CodeContext.h"
#include "comm/Connection.h"
#include "comm/Tcp.h"
#include "security/ServerOptions.h"

namespace AnyP
{

class PortCfg : public CodeContext
{
public:
    PortCfg();
    // no copying/moving but see ipV4clone() and update()
    PortCfg(PortCfg &&) = delete;
    ~PortCfg() override;

    /// creates the same port configuration but listening on any IPv4 address
    PortCfg *ipV4clone() const;

    /// apply new configuration while preserving current listening socket
    void update(const PortCfg &fresh);

    /* CodeContext API */
    ScopedId codeContextGist() const override;
    std::ostream &detailCodeContext(std::ostream &os) const override;

    PortCfgPointer next;

    Ip::Address s;
    AnyP::ProtocolVersion transport; ///< transport protocol and version received by this port
    char *name;                /* visible name */
    char *defaultsite;         /* default web site */

    TrafficMode flags;  ///< flags indicating what type of traffic to expect via this port.

    bool allow_direct;       ///< Allow direct forwarding in accelerator mode
    bool vhost;              ///< uses host header
    bool actAsOrigin;        ///< update replies to conform with RFC 2616
    bool ignore_cc;          ///< Ignore request Cache-Control directives

    bool connection_auth_disabled; ///< Don't support connection oriented auth

    bool ftp_track_dirs; ///< whether transactions should track FTP directories

    int vport;               ///< virtual port support. -1 if dynamic, >0 static
    int disable_pmtu_discovery;
    bool workerQueues; ///< whether listening queues should be worker-specific

    Comm::TcpKeepAlive tcp_keepalive;

    /**
     * The listening socket details.
     * If Comm::ConnIsOpen() we are actively listening for client requests.
     * use listenConn->close() to stop.
     */
    Comm::ConnectionPointer listenConn;

    /// TLS configuration options for this listening port
    Security::ServerOptions secure;

private:
    PortCfg(const PortCfg &other, const Ip::Address &customAddrress);
};

/// reports brief port identification (for debugging)
std::ostream &operator <<(std::ostream &, const PortCfg &);

} // namespace AnyP

/// list of Squid http(s)_port configured
extern AnyP::PortCfgPointer HttpPortList;

/// list of Squid ftp_port configured
extern AnyP::PortCfgPointer FtpPortList;

/// replaces configuration of a matching listed port with a given new one
/// \sa AnyP::PortCfg::update()
void UpdatePortCfg(const AnyP::PortCfgPointer &list, const AnyP::PortCfg &newCfg);

#if !defined(MAXTCPLISTENPORTS)
// Max number of TCP listening ports
#define MAXTCPLISTENPORTS 128
#endif

// TODO: kill this global array. Need to check performance of array vs list though.
extern int NHttpSockets;
extern int HttpSockets[MAXTCPLISTENPORTS];

#endif /* SQUID_SRC_ANYP_PORTCFG_H */

