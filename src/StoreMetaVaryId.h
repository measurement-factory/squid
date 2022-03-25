/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREMETAVARY_ID_H
#define SQUID_STOREMETAVARY_ID_H

#include "StoreMeta.h"

class StoreMetaVaryId : public StoreMeta
{
    MEMPROXY_CLASS(StoreMetaVaryId);

public:
    char getType() const { return STORE_META_VARY_ID; }
    bool checkConsistency(StoreEntry *e) const;
};

#endif /* SQUID_STOREMETAVARY_ID_H */

