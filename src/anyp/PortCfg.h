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

    /// internal name (if provided) or specification
    const char *name() const  { return name_ ? name_ : spec_; }

    /// assigns the internal name
    void initName(const char *aName) { assert(!name_); name_ = xstrdup(aName); }

    /// assigns the specification
    void initSpec(const char *aSpec) { assert(!spec_); spec_ = xstrdup(aSpec); }

    PortCfgPointer next;

    Ip::Address s;
    AnyP::ProtocolVersion transport; ///< transport protocol and version received by this port
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
    char *name_; ///< internal name for the port
    char *spec_; ///< the port specification (port or addr:port)
};

/// Iterates over a PortCfg list and sets the corresponding CodeContext before each iteration.
class PortIterator
{
public:
    // some of the standard iterator traits
    using iterator_category = std::forward_iterator_tag;
    using value_type = PortCfgPointer;
    using pointer = value_type *;
    using reference = value_type &;

    /// \param first the PortCfg this iterator points to
    PortIterator(const PortCfgPointer &first): position_(first) { setContext(); }
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

/// A range of port configurations.
class PortCfgRange
{
public:
    /// \param first the start of the range
    explicit PortCfgRange(AnyP::PortCfgPointer &first): first_(first), savedContext(CodeContext::Current()) {}
    ~PortCfgRange() { CodeContext::Reset(savedContext); }

    PortIterator begin() const { return PortIterator(first_); }
    PortIterator end() const { return PortIterator(); }

private:
    AnyP::PortCfgPointer first_;
    CodeContext::Pointer savedContext; ///< the old context
};

} // namespace AnyP

/// list of Squid http(s)_port configured
extern AnyP::PortCfgPointer HttpPortList;

AnyP::PortCfgRange HttpPorts();

/// list of Squid ftp_port configured
extern AnyP::PortCfgPointer FtpPortList;

AnyP::PortCfgRange FtpPorts();

#if !defined(MAXTCPLISTENPORTS)
// Max number of TCP listening ports
#define MAXTCPLISTENPORTS 128
#endif

// TODO: kill this global array. Need to check performance of array vs list though.
extern int NHttpSockets;
extern int HttpSockets[MAXTCPLISTENPORTS];

#endif /* SQUID_ANYP_PORTCFG_H */

