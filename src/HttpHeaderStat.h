/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTPHEADERSTAT_H
#define SQUID_SRC_HTTPHEADERSTAT_H

#include "HttpHdrCc.h"
#include "HttpHdrSc.h"
#include "StatHist.h"

/// HTTP per header statistics
class HttpHeaderStat
{
public:
    HttpHeaderStat() :
        label(nullptr),
        owner_mask(nullptr),
        parsedCount(0),
        ccParsedCount(0),
        scParsedCount(0),
        destroyedCount(0),
        busyDestroyedCount(0)
    {
        hdrUCountDistr.enumInit(32);    /* not a real enum */
        fieldTypeDistr.enumInit(Http::HdrType::enumEnd_);
        ccTypeDistr.enumInit(HttpHdrCcType::CC_ENUM_END);
        scTypeDistr.enumInit(SC_ENUM_END);
    }

    HttpHeaderStat(const char *aLabel, HttpHeaderMask *aMask) :
        label(aLabel),
        owner_mask(aMask),
        parsedCount(0),
        ccParsedCount(0),
        scParsedCount(0),
        destroyedCount(0),
        busyDestroyedCount(0)
    {
        assert(label);
        hdrUCountDistr.enumInit(32);    /* not a real enum */
        fieldTypeDistr.enumInit(Http::HdrType::enumEnd_);
        ccTypeDistr.enumInit(HttpHdrCcType::CC_ENUM_END);
        scTypeDistr.enumInit(SC_ENUM_END);
    }

    // nothing to destruct as label is a pointer to global const string
    // and owner_mask is a pointer to global static array
    ~HttpHeaderStat() {}

    const char *label;
    HttpHeaderMask *owner_mask;

    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;
    StatHist scTypeDistr;

    int parsedCount;
    int ccParsedCount;
    int scParsedCount;
    int destroyedCount;
    int busyDestroyedCount;
};

#endif /* SQUID_SRC_HTTPHEADERSTAT_H */

