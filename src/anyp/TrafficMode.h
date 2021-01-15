/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ANYP_TRAFFIC_MODE_H
#define SQUID_ANYP_TRAFFIC_MODE_H

namespace AnyP
{

/**
 * Set of 'mode' flags defining types of trafic which can be received.
 *
 * Use to determine the processing steps which need to be applied
 * to this traffic under any special circumstances which may apply.
 */
class TrafficMode
{
public:
    /// This port handles traffic that has been intercepted prior to being delivered
    /// to the TCP client of the accepted connection and/or to us. This port mode
    /// alone does not imply that the client of the accepted TCP connection was not
    /// connecting directly to this port (since commit 151ba0d).
    bool interceptedSomewhere() const { return natIntercept_ || tproxyIntercept_ || proxySurrogateHttps_; }

    /// The client of the accepted TCP connection was connecting to this port.
    /// The accepted traffic may have been intercepted earlier!
    bool tcpToUs() const { return proxySurrogate() || !interceptedSomewhere(); }

    /// The client of the accepted TCP connection was not connecting to this port.
    /// The accepted traffic may have been intercepted earlier as well!
    bool interceptedLocally() const { return interceptedSomewhere() && !tcpToUs(); }

    // Unused yet.
    /// This port handles traffic that has been intercepted prior to being delivered
    /// to the TCP client of the accepted connection (which then connected to us).
    bool interceptedRemotely() const { return interceptedSomewhere() && tcpToUs(); }

    /// The client of the accepted TCP connection was connecting directly to this proxy port
    bool forwarded() const { return !interceptedSomewhere() && !accelSurrogate; }

    /// whether the PROXY protocol header is required
    bool proxySurrogate() const { return proxySurrogateHttp_ || proxySurrogateHttps_; }

    /** marks http ports receiving PROXY protocol traffic
     *
     * Indicating the following are required:
     *  - PROXY protocol magic header
     *  - src/dst IP retrieved from magic PROXY header
     *  - indirect client IP trust verification is mandatory
     *  - TLS is not supported
     */
    void proxySurrogateHttp(const bool val) { proxySurrogateHttp_ = val; }
    bool proxySurrogateHttp() const { return proxySurrogateHttp_; }

    /** marks https ports receiving PROXY protocol traffic
     *
     * Indicating the following are required:
     *  - PROXY protocol magic header
     *  - URL translation from relative to absolute form
     *  - src/dst IP retrieved from magic PROXY header
     *  - indirect client IP trust verification is mandatory
     *  - Same-Origin verification is mandatory
     *  - TLS is supported
     *  - proxy authentication prohibited
     */
    void proxySurrogateHttps(const bool val) { proxySurrogateHttps_ = val; }
    bool proxySurrogateHttps() const { return proxySurrogateHttps_; }

    /** marks NAT intercepted traffic
     *
     * Indicating the following are required:
     *  - NAT lookups
     *  - URL translation from relative to absolute form
     *  - Same-Origin verification is mandatory
     *  - destination pinning is recommended
     *  - proxy authentication prohibited
     */
    void natIntercept(const bool val) { natIntercept_ = val; }
    bool natIntercept() const { return natIntercept_; }
    bool natInterceptLocally() const { return natIntercept_ && !tcpToUs(); }

    /** marks TPROXY intercepted traffic
     *
     * Indicating the following are required:
     *  - src/dst IP inversion must be performed
     *  - client IP should be spoofed if possible
     *  - URL translation from relative to absolute form
     *  - Same-Origin verification is mandatory
     *  - destination pinning is recommended
     *  - proxy authentication prohibited
     */
    void tproxyIntercept(const bool val) { tproxyIntercept_ = val; }
    bool tproxyIntercept() const { return tproxyIntercept_; }
    bool tproxyInterceptLocally() const { return tproxyIntercept_ && !tcpToUs(); }

    /** marks HTTP accelerator (reverse/surrogate proxy) traffic
     *
     * Indicating the following are required:
     *  - URL translation from relative to absolute form
     *  - restriction to origin peer relay recommended
     */
    bool accelSurrogate = false;

    /** marks intercept and decryption of CONNECT (tunnel) SSL traffic
     *
     * Indicating the following are required:
     *  - decryption of CONNECT request
     *  - URL translation from relative to absolute form
     *  - authentication prohibited on unwrapped requests (only on the CONNECT tunnel)
     *  - encrypted outbound server connections
     *  - peer relay prohibited. TODO: re-encrypt and re-wrap with CONNECT
     */
    bool tunnelSslBumping = false;

private:

    bool proxySurrogateHttp_ = false;

    bool proxySurrogateHttps_ = false;

    bool natIntercept_ = false;

    bool tproxyIntercept_ = false;
};

} // namespace AnyP

#endif

