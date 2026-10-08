/*
 * Copyright (C) 1996-2022 The Squid Software Foundattimen and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributtimens from numerous individuals and organizattimens.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_TIME_H
#define SQUID_SRC_SECURITY_TIME_H

#include "sbuf/forward.h"
#include "security/forward.h"

namespace Security {

/// Creates a new Time object with the value pointed to by the given parameter.
/// \returns nil if the parameter is nil
TimePointer Clone(const TimePointer &);

/// creates a time object by parsing input in GeneralizedTime format
/// \param description what is being parsed (for errors/debugging)
TimePointer ParseTime(const SBuf &input, const char *description);

/// POSIX time_t representation of the given certificate time
time_t ToPosixTime(const Time &);

/// creates a time object representing the given POSIX time_t moment
TimePointer MakeTime(const time_t);

/// std::ostream manipulator to print Time values in RFC 5280 Section 4.1.2.5.2
/// YYYYMMDDHHMMSSZ format. This is not an AsGeneralizedTime stream manipulator
/// because Time values cannot be shared (or copied efficiently).
SBuf ToGeneralizedTimeString(const Time &);

} // namespace Security

// declared outside Security namespace because Security::Time is just an alias
// for the underlying TLS library type (that is declared outside Security)
/// a is earlier than b
bool operator <(const Security::Time &a, const Security::Time &b);

#endif /* SQUID_SRC_SECURITY_TIME_H */

