/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"

#include "base/RandomUuid.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreMetaVaryId.h"

bool
StoreMetaVaryId::checkConsistency(StoreEntry *e) const
{
    assert(getType() == STORE_META_VARY_ID);

    RandomUuid uuid;
    uuid.load(value, length);
    if (!e->mem_obj->varyUuid.has_value()) {
        e->mem_obj->varyUuid = std::move(uuid);
        return true;
    }
    return e->mem_obj->varyUuid.value() == uuid;
}

