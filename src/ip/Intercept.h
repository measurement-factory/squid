/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 89    NAT / IP Interception */

#ifndef SQUID_IP_IPINTERCEPT_H
#define SQUID_IP_IPINTERCEPT_H

/* for time_t */
#include "SquidTime.h"

namespace Ip
{

class Address;

/**
 \defgroup IpInterceptAPI IP Interception and Transparent Proxy API
 \ingroup SquidComponent
 \par
 * There is no formal state-machine for transparency and interception
 * instead there is this neutral API which other connection state machines
 * and the comm layer use to co-ordinate their own state for transparency.
 */
class Intercept
{
public:
    Intercept() : transparentActive_(0), interceptActive_(0), lastReported_(0) {};
    ~Intercept() {};

    /// perform NAT lookups
    bool LookupNat(const Comm::ConnectionPointer &newConn);
    /// perform Tproxy lookups
    bool LookupTproxy(const Comm::ConnectionPointer &newConn);

    /**
     * Test system networking calls for TPROXY support.
     * Detects IPv6 and IPv4 level of support matches the address being listened on
     * and if the compiled v2/v4 is usable as far down as a bind()ing.
     *
     * \param test    Address set on the squid.conf *_port being checked.
     * \retval true   TPROXY is available.
     * \retval false  TPROXY is not available.
     */
    bool ProbeForTproxy(Address &test);

    /**
     \retval 0  Full transparency is disabled.
     \retval 1  Full transparency is enabled and active.
     */
    inline int TransparentActive() { return transparentActive_; };

    /** \par
     * Turn on fully Transparent-Proxy activities.
     * This function should be called during parsing of the squid.conf
     * When any option requiring full-transparency is encountered.
     */
    inline void StartTransparency() { transparentActive_=1; };

    /** \par
     * Turn off fully Transparent-Proxy activities on all new connections.
     * Existing transactions and connections are unaffected and will run
     * to their natural completion.
     \param str    Reason for stopping. Will be logged to cache.log
     */
    void StopTransparency(const char *str);

    /**
     \retval 0  IP Interception is disabled.
     \retval 1  IP Interception is enabled and active.
     */
    inline int InterceptActive() { return interceptActive_; };

    /** \par
     * Turn on IP-Interception-Proxy activities.
     * This function should be called during parsing of the squid.conf
     * When any option requiring interception / NAT handling is encountered.
     */
    inline void StartInterception() { interceptActive_=1; };

    /** \par
     * Turn off IP-Interception-Proxy activities on all new connections.
     * Existing transactions and connections are unaffected and will run
     * to their natural completion.
     \param str    Reason for stopping. Will be logged to cache.log
     */
    inline void StopInterception(const char *str);

private:

    /**
     * perform Lookups on fully-transparent interception targets (TPROXY).
     * Supports Netfilter, PF and IPFW.
     *
     * \param newConn  Details known, to be updated where relevant.
     * \return         Whether successfully located the new address.
     */
    bool TproxyTransparent(const Comm::ConnectionPointer &newConn);

    /**
     * perform Lookups on Netfilter interception targets (REDIRECT, DNAT).
     *
     * \param newConn  Details known, to be updated where relevant.
     * \return         Whether successfully located the new address.
     */
    bool NetfilterInterception(const Comm::ConnectionPointer &newConn);

    /**
     * perform Lookups on IPFW interception.
     *
     * \param newConn  Details known, to be updated where relevant.
     * \return         Whether successfully located the new address.
     */
    bool IpfwInterception(const Comm::ConnectionPointer &newConn);

    /**
     * perform Lookups on IPF interception.
     *
     * \param newConn  Details known, to be updated where relevant.
     * \return         Whether successfully located the new address.
     */
    bool IpfInterception(const Comm::ConnectionPointer &newConn);

    /**
     * perform Lookups on PF interception target (REDIRECT).
     *
     * \param newConn  Details known, to be updated where relevant.
     * \return         Whether successfully located the new address.
     */
    bool PfInterception(const Comm::ConnectionPointer &newConn);

    int errorReportingLevel();

    int transparentActive_;
    int interceptActive_;
    time_t lastReported_; /**< Time of last error report. Throttles NAT error display to 1 per minute */
};

#if LINUX_NETFILTER && !defined(IP_TRANSPARENT)
/// \ingroup IpInterceptAPI
#define IP_TRANSPARENT 19
#endif

/**
 \ingroup IpInterceptAPI
 * Globally available instance of the IP Interception manager.
 */
extern Intercept Interceptor;

} // namespace Ip

#endif /* SQUID_IP_IPINTERCEPT_H */

