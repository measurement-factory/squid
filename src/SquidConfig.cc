/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store/Disks.h"

class SquidConfig Config;

class SquidConfig2 Config2;

void
Store::DiskConfig::dump(StoreEntry *entry, const char *name) const
{
   assert(entry);
   for (int i = 0; i < n_configured; ++i) {
       auto &disk = Disks::Dir(i);
       storeAppendPrintf(entry, "%s %s %s", name, disk.type(), disk.path);
       disk.dump(*entry);
       storeAppendPrintf(entry, "\n");
   }
}

