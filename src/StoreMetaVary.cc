/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "base/TextException.h"
#include "MemObject.h"
#include "sbuf/Stream.h"
#include "Store.h"
#include "StoreMetaVary.h"

void
StoreMetaVary::applyTo(StoreEntry *e) const
{
    assert (getType() == STORE_META_VARY_HEADERS);

    if (e->mem_obj->vary_headers.isEmpty()) {
        /* Assume the object is OK.. remember the vary request headers */
        e->mem_obj->vary_headers.assign(static_cast<const char *>(value), length);
        /* entries created before SBuf vary handling may include string terminator */
        static const SBuf nul("\0", 1);
        e->mem_obj->vary_headers.trim(nul);
        return;
    }

    const auto loadedVary = static_cast<const char *>(value);
    if (e->mem_obj->vary_headers.cmp(loadedVary, length) != 0)
        throw TextException(ToSBuf("Vary headers mismatch: {", loadedVary, "} != {", e->mem_obj->vary_headers), Here());
}

