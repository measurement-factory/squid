/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_DIRECTIVE_RULES_H
#define SQUID_ACL_DIRECTIVE_RULES_H

#include "acl/forward.h"

namespace Acl
{

/// Combined rules of an ACL-driven configuration directive.
/// Updated during smooth_reconfiguration.
class DirectiveRules
{
public:
    DirectiveRules(const char *directiveName, const char *directiveCfg);
    ~DirectiveRules();
    DirectiveRules(DirectiveRules &&) = delete;

    RefCount<Acl::Tree> raw;
};

/// update ACL-driven configuration directives to use newly reconfigured ACLs
/// \param dryRun whether to just simulate the update, preserving directives
void SyncDirectiveRules(bool dryRun);

} // namespace Acl

#endif /* SQUID_ACL_DIRECTIVE_RULES_H */

