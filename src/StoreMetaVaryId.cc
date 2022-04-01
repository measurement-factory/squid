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

    if (length < 0 || static_cast<size_t>(length) != sizeof(RandomUuid::Serialized))
        return false;

    if (!value)
        return false;

    const auto serialized = reinterpret_cast<const RandomUuid::Serialized*>(value);
    RandomUuid uuid(*serialized);

    // XXX: We should not be changing anything in a checkConsistency() method!

    if (!e->mem_obj->varyUuid.has_value()) {
        e->mem_obj->varyUuid = std::move(uuid);
        return true;
    }
    return e->mem_obj->varyUuid.value() == uuid;
}

