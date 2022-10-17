/*
 * Copyright (C) 1996-2022 The Squid Software Foundattimen and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributtimens from numerous individuals and organizattimens.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "sbuf/Stream.h"
#include "security/Time.h"

#include <ctime>

#if USE_OPENSSL
Security::TimePointer
Security::ParseTime(const char * const generalizedTime, const char * const description)
{
    assert(generalizedTime);
    debugs(33, DBG_PARSE_NOTE(2), description << ": " << generalizedTime);

#if USE_OPENSSL
    std::unique_ptr<ASN1_TIME> t(ASN1_TIME_set(nullptr, 0));
    if (!t)
        throw TextException(ToSBuf("ASN1_TIME_set() failed to allocate an ASN1_TIME structure for parsing ", description), Here());
#if HAVE_LIBCRYPTO_ASN1_TIME_SET_STRING
    if (!ASN1_TIME_set_string(t.get(), generalizedTime))
        throw TextException(ToSBuf("ASN1_TIME_set_string() failed to parse ", description, ": ", generalizedTime), Here());
#else
    throw TextException(ToSBuf("Need OpenSSL version providing ASN1_TIME_set_string() to parse ", description), Here());
#endif
    return t;
#elif USE_GNUTLS
    throw TextException(ToSBuf("Missing GnuTLS support for parsing ", description), Here());
    return nullptr;
#else
    throw TextException(ToSBuf("TLS library required to parse ", description), Here());
    return nullptr;
#endif
}

// XXX: Add GnuTLS/other support.
// TODO: Consider adding an ASN1_TIME_to_tm() replacement, even though this
// function is currently only used for better diagnostics of config problems?
time_t
Security::ToPosixTime(const Time &from)
{
#if HAVE_LIBCRYPTO_ASN1_TIME_TO_TM
    std::tm resultTm = {};
    if (!ASN1_TIME_to_tm(&from, &resultTm))
        throw TextException("ASN1_TIME_to_tm() failure", Here());
    const auto resultPosix = timegm(&resultTm);
    if (resultPosix < 0)
        throw TextException("timegm() failure", Here());
    return resultPosix;
#else
    throw TextException("This OpenSSL version does not support ASN1_TIME_to_tm()", Here());
#endif
}

#if USE_OPENSSL
/// Print the time represented by a ASN1_TIME struct to a string using GeneralizedTime format
static bool
asn1timeToGeneralizedTimeStr(const ASN1_TIME *aTime, char *buf, const int bufLen)
{
    // ASN1_Time  holds time to UTCTime or GeneralizedTime form.
    // UTCTime has the form YYMMDDHHMMSS[Z | [+|-]offset]
    // GeneralizedTime has the form YYYYMMDDHHMMSS[Z | [+|-] offset]

    // length should have space for data plus 2 extra bytes for the two extra year fields
    // plus the '\0' char.
    if ((aTime->length + 3) > bufLen)
        return false;

    char *str;
    if (aTime->type == V_ASN1_UTCTIME) {
        if (aTime->data[0] > '5') { // RFC 2459, section 4.1.2.5.1
            buf[0] = '1';
            buf[1] = '9';
        } else {
            buf[0] = '2';
            buf[1] = '0';
        }
        str = buf +2;
    } else // if (aTime->type == V_ASN1_GENERALIZEDTIME)
        str = buf;

    memcpy(str, aTime->data, aTime->length);
    str[aTime->length] = '\0';
    return true;
}

static int
asn1time_cmp(const ASN1_TIME *asnTime1, const ASN1_TIME *asnTime2)
{
    // TODO: Use ASN1_TIME_compare() when built with OpenSSL v1.1.1 or later.
    // TODO: Throw on failures instead of lying about asnTime1 < asnTime2!
    char strTime1[64], strTime2[64];
    if (!asn1timeToGeneralizedTimeStr(asnTime1, strTime1, sizeof(strTime1)))
        return -1;
    if (!asn1timeToGeneralizedTimeStr(asnTime2, strTime2, sizeof(strTime2)))
        return -1;

    return strcmp(strTime1, strTime2);
}
#endif // USE_OPENSSL

bool
operator <(const Security::Time &a, const Security::Time &b)
{
#if USE_OPENSSL
    return asn1time_cmp(&a, &b) < 0;
#else
#error XXX: Implement for GnuTLS and others
#endif
}

#endif // USE_OPENSSL

