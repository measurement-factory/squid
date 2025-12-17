/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_KEY_LOGGER_H
#define SQUID_SRC_SECURITY_KEY_LOGGER_H

#include "acl/forward.h"
#include "security/forward.h"

namespace Security {

/// Makes key logging possible for future TLS connections created with the given context.
/// \prec the given context pointer is not nil; TODO: Add Context type to use a reference instead.
void EnableKeyLogging(ContextPointer &);

/// Creates a logger for the given connection (if needed and possible).
/// \prec EnableKeyLogging() has been called for the connection context
void KeyLoggingStart(Connection &, const Acl::ChecklistFiller &);

/// Logs connection secrets if logging is needed and possible.
/// Should be called whenever new connection secrets may appear.
/// Optimized for making quick "no need" decisions.
/// Avoids writing identical log records, making repeated calls safe.
void KeyLoggingCheckpoint(const Connection &);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_KEY_LOGGER_H */

