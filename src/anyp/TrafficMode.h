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
    /// whether the PROXY protocol header is present
    bool proxySurrogate() const { return proxySurrogateHttp_ || proxySurrogateHttps_; }

    /** Whether the incoming client traffic will be treated by Squid as intercepted,
     * according to the listening port configuration.
     * This can be either the TCP traffic, directed to origin or
     * HTTP(S) traffic, preceded by the PROXY protocol header.
     * - Same-Origin verification is mandatory
     * - URL translation from relative to absolute form
     * - proxy authentication prohibited
     */
    bool intercepted() const {
        return natIntercept_ || tproxyIntercept_ || proxySurrogateHttps_;
    }

    /** whether the client TCP traffic is directed to the Squid instance
     */
    bool forwarded() const {
        return !intercepted() && !accelSurrogate;
    }

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

