/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/DirectiveRules.h"
#include "acl/Tree.h"
#include "Debug.h"

#include <unordered_set>

namespace Acl {

using Registrations = std::unordered_set<DirectiveRules* /* XXX: Pool */>;

/// all known ACL-driven directives
static
Registrations &
Registered()
{
    static const auto registered = new Registrations();
    return *registered;
}

} // namespace Acl

Acl::DirectiveRules::DirectiveRules(const char * const directiveName, const char * const directiveCfg):
    raw(new Tree())
{
    raw->context(directiveName, directiveCfg);

    const auto insertion = Registered().insert(this);
    assert(insertion.second); // no duplicates
}

Acl::DirectiveRules::~DirectiveRules()
{
    const auto count = Registered().erase(this);
    assert(count > 0); // no unknowns
    assert(count < 2); // no duplicates
}

void
Acl::SyncDirectiveRules(const bool dryRun)
{
    debugs(28, 5, Registered().size() << " registrations; dryRun=" << dryRun);
    for (auto &drules: Registered()) {
        if (const auto &tree = drules->raw) {
            const auto syncedAcl = tree->makeSyncedVersion();
            if (dryRun) {
                delete syncedAcl;
            } else {
                const auto syncedTree = dynamic_cast<Acl::Tree*>(syncedAcl);
                assert(syncedTree);
                drules->raw = syncedTree;
            }
        }
    }
}

