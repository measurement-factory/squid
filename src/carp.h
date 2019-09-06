/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 39    Cache Array Routing Protocol */

#ifndef SQUID_CARP_H_
#define SQUID_CARP_H_

class CachePeer;
class HttpRequest;
class ps_state;

void carpInit(void);
CachePeer *carpSelectParent(HttpRequest *, ps_state *);

#endif /* SQUID_CARP_H_ */

