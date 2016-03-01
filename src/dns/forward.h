/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_DNS_FORWARD_H
#define _SQUID_SRC_DNS_FORWARD_H

namespace Ip
{
class Address;
}

class rfc1035_rr;

typedef void IDNSCB(void *, const rfc1035_rr *, int, const char *);

// generic DNS API
namespace Dns
{

class LookupDetails;

void Init(void);
void Shutdown(void);

} // namespace Dns

// internal DNS client API
void idnsALookup(const char *, IDNSCB *, void *);
void idnsPTRLookup(const Ip::Address &, IDNSCB *, void *);

#endif /* _SQUID_SRC_DNS_FORWARD_H */

