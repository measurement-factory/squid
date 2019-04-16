/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef HTTPHEADERSTAT_H_
#define HTTPHEADERSTAT_H_

#include "StatHist.h"

/// per header statistics
class HttpHeaderStat
{
public:
    const char *label = nullptr;
    HttpHeaderMask *owner_mask = nullptr;

    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;
    StatHist scTypeDistr;

    int parsedCount = 0;
    int ccParsedCount = 0;
    int scParsedCount = 0;
    int destroyedCount = 0;
    int busyDestroyedCount = 0;
};

#endif /* HTTPHEADERSTAT_H_ */

