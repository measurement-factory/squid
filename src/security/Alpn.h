/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_ALPN_H
#define SQUID_SRC_SECURITY_ALPN_H

#include "security/Context.h"

namespace Security {

/// enable observation of the ALPN protocols offered by the client during TLS negotiation
/// \prec the given context pointer is not nil
void EnableClientAlpnObservation(ContextPointer &);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_ALPN_H */

