/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "CachePeer.h"
#include "defines.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "SquidConfig.h"
#include "util.h"

CBDATA_CLASS_INIT(CachePeer);

CachePeer::CachePeer(const char * const hostname):
    name(xstrdup(hostname)),
    host(name)
{
    Tolower(host);
}

CachePeer::~CachePeer()
{
    if (explicitlyNamed())
        xfree(name);

    xfree(host);

    while (NeighborTypeDomainList *l = typelist) {
        typelist = l->next;
        xfree(l->domain);
        xfree(l);
    }

    aclDestroyAccessList(&access);

#if USE_CACHE_DIGESTS
    cbdataReferenceDone(digest);
    xfree(digest_url);
#endif

    delete next;

    xfree(login);

    delete standby.pool;

    // the mgr job will notice that its owner is gone and stop
    PeerPoolMgr::Checkpoint(standby.mgr, "peer gone");

    xfree(domain);
}

void
CachePeer::rename(const char * const newName)
{
    if (!newName || !*newName)
        throw TextException("cache_peer name=value cannot be empty", Here());

    if (explicitlyNamed())
        xfree(name);

    name = xstrdup(newName);
}

time_t
CachePeer::connectTimeout() const
{
    if (connect_timeout_raw > 0)
        return connect_timeout_raw;
    return Config.Timeout.peer_connect;
}

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.name;
}

