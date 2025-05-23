/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_TYPE_H
#define SQUID_SRC_AUTH_TYPE_H

#if USE_AUTH

namespace Auth
{

typedef enum {
    AUTH_UNKNOWN,               /* default */
    AUTH_BASIC,
    AUTH_NTLM,
    AUTH_DIGEST,
    AUTH_NEGOTIATE,
    AUTH_BROKEN                 /* known type, but broken data */
} Type;

extern const char *Type_str[];

}; // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_TYPE_H */

