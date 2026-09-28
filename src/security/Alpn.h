/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_ALPN_H
#define SQUID_SRC_SECURITY_ALPN_H

#include "sbuf/SBuf.h"
#include "security/Context.h"
#include "security/Session.h"

#include <vector>

namespace Security {

/// TLS ALPN extension protocol names, in the order the peer listed them
using AlpnProtocols = std::vector<SBuf>;

/// enable observation of the ALPN protocols offered by the client during TLS negotiation
/// \prec the given context pointer is not nil
void EnableClientAlpnObservation(ContextPointer &);

/// splits a raw TLS ALPN extension protocol list into individual protocol names
AlpnProtocols ParseAlpnList(const SBuf &rawList);

/// protocol names that EnableClientAlpnObservation() saw the client offer
/// \returns an empty container if the client did not offer any ALPN protocols
AlpnProtocols ObservedClientAlpns(const SessionPointer &);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_ALPN_H */

