/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ANYP_PORTCFG_H
#define SQUID_ANYP_PORTCFG_H

#include "anyp/forward.h"
#include "anyp/ProtocolVersion.h"
#include "anyp/TrafficMode.h"
#include "base/CodeContext.h"
#include "comm/Connection.h"
#include "comm/Tcp.h"
#include "sbuf/SBuf.h"
#include "security/ServerOptions.h"

namespace AnyP
{

class PortCfg : public CodeContext
{
public:
    PortCfg();
    // no public copying/moving but see ipV4clone()
    PortCfg(PortCfg &&) = delete;
    ~PortCfg();

    /// creates the same port configuration but listening on any IPv4 address
    PortCfg *ipV4clone() const;

    /* CodeContext API */
    virtual ScopedId codeContextGist() const override;
    virtual std::ostream &detailCodeContext(std::ostream &os) const override;

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
    explicit PortCfg(const PortCfg &other); // for ipV4clone() needs only!
};

/// iterates over a PortCfg list
class PortIterator
{
public:
    // some of the standard iterator traits
    using iterator_category = std::forward_iterator_tag;
    using value_type = PortCfgPointer;
    using pointer = value_type *;
    using reference = value_type &;

    explicit PortIterator(const PortCfgPointer &first): position_(first) {}
    // special constructor for end() iterator
    PortIterator(): position_(nullptr) {}

    reference operator *() { return position_; }
    pointer operator ->() { return &position_; }

    PortIterator& operator++() { position_ = position_->next; setContext(); return *this; }
    PortIterator operator++(int) { const auto oldMe = *this; ++(*this); return oldMe; }

    bool operator ==(const PortIterator &them) const { return position_ == them.position_; }
    bool operator !=(const PortIterator &them) const { return !(*this == them); }

    void setContext() { if (position_) CodeContext::Reset(position_); }

protected:

    value_type position_; ///< current iteration location
};

/// Decides which list of port configurations to iterate in range-based for loops.
class PortCfgSelector
{
public:
    explicit PortCfgSelector(AnyP::PortCfgPointer &p): first_(p), savedContext(CodeContext::Current()) {}
    ~PortCfgSelector() { CodeContext::Reset(savedContext); }

    PortIterator begin() const { PortIterator it{first_}; it.setContext(); return it; }
    PortIterator end() const { return PortIterator(); }

private:
    AnyP::PortCfgPointer first_;
    CodeContext::Pointer savedContext;
};

} // namespace AnyP

/// list of Squid http(s)_port configured
extern AnyP::PortCfgPointer HttpPortList;

AnyP::PortCfgSelector HttpPorts();

/// list of Squid ftp_port configured
extern AnyP::PortCfgPointer FtpPortList;

AnyP::PortCfgSelector FtpPorts();

#if !defined(MAXTCPLISTENPORTS)
// Max number of TCP listening ports
#define MAXTCPLISTENPORTS 128
#endif

// TODO: kill this global array. Need to check performance of array vs list though.
extern int NHttpSockets;
extern int HttpSockets[MAXTCPLISTENPORTS];

#endif /* SQUID_ANYP_PORTCFG_H */

