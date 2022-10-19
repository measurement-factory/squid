/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "security/Time.h"
#include "SquidTime.h"
#include "ssl/gadgets.h"
#include "ssl/ProxyCerts.h"

#if USE_OPENSSL

void
CheckValidityRangeFreshness(sslproxy_cert_adapt &ca, const Security::Time &from, const Security::Time &to)
{
    assert(ca.alg == Ssl::algSetValidityRange);
    debugs(33, 5, ca.param << " at " << squid_curtime << '<' << ca.nextValidityRangeFreshnessCheck);
    if (squid_curtime < ca.nextValidityRangeFreshnessCheck)
        return; // either still fresh and good or stale and reported

    try {
        const Security::TimePointer now(ASN1_TIME_set(nullptr, squid_curtime));
        if (!now)
            throw TextException("ASN1_TIME_set(current_time) failure", Here());
        if (*now < from)
            throw TextException("setValidityRange has not started yet", Here());
        if (to < *now)
            throw TextException("setValidityRange has already ended", Here());

        // looks good now, but check again when the validity period ends
        ca.nextValidityRangeFreshnessCheck = Security::ToPosixTime(to);
        return;
    } catch (...) {
        debugs(33, DBG_CRITICAL, "ERROR: Using problematic or unverifiable " <<
               "sslproxy_cert_adapt setValidityRange {" << ca.param << '}' <<
               Debug::Extra << "problem: " << CurrentException);
    }

    // do not check anymore (i.e. until the end of time)
    ca.nextValidityRangeFreshnessCheck = std::numeric_limits<decltype(ca.nextValidityRangeFreshnessCheck)>::max();
}

#endif

