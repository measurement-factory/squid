/*
 * Copyright (C) 1996-2022 The Squid Software Foundattimen and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributtimens from numerous individuals and organizattimens.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_TIME_H
#define SQUID_SRC_SECURITY_TIME_H

#include "security/forward.h"

namespace Security {

/// creates a time object by parsing input in GeneralizedTime format
/// \param description what is being parsed (for errors/debugging)
TimePointer ParseTime(const char *input, const char *description);

/// POSIX time_t representation of the given certificate time
time_t ToPosixTime(const Time &);

} // namespace Security

// declared outside Security namespace because Security::Time is just an alias
// for the underlying TLS library type (that is declared outside Security)
/// a is earlier than b
bool operator <(const Security::Time &a, const Security::Time &b);

#endif /* SQUID_SRC_SECURITY_TIME_H */

