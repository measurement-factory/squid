/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "XactionStep.h"

#include <iostream>

const char *
XactionStepName(const XactionStep xstep)
{
    // keep in sync with XactionStep
    static const char *StepNames[static_cast<int>(XactionStep::enumEnd_)] = {
        "[unknown step]"
        ,"GeneratingCONNECT"
#if USE_OPENSSL
        ,"SslBump1"
        ,"SslBump2"
        ,"SslBump3"
        ,"[SslBump done]"
#endif
    };

    assert(XactionStep::enumBegin_ <= xstep && xstep < XactionStep::enumEnd_);
    return StepNames[static_cast<int>(xstep)];
}

std::ostream &
operator <<(std::ostream &os, const XactionStep step)
{
    if (XactionStep::enumBegin_ <= step && step < XactionStep::enumEnd_)
        os << XactionStepName(step);
    else
        os << "[invalid step " << int(step) << ']';
    return os;
}

