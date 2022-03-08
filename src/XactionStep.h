/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_XACTIONSTEPS_H
#define SQUID_XACTIONSTEPS_H

#include <iosfwd>

enum class XactionStep  {
    enumBegin_ = 0, // for WholeEnum iteration
    unknown = enumBegin_,
    generatingConnect,
#if USE_OPENSSL
    tlsBump1,
    tlsBump2,
    tlsBump3,
    tlsBumpDone,
#endif
    enumEnd_ // for WholeEnum iteration
};

/// Converts XactionStep value to its human-friendly name (with a string literal
/// lifetime). These step names are those used for at_step rules in squid.conf.
const char *XactionStepName(XactionStep);

/// report a human-friendly transaction step name (for debugging)
std::ostream &operator <<(std::ostream &, XactionStep);

#endif /* SQUID_XACTIONSTEPS_H */

