/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_FORWARD_H
#define SQUID_ACL_FORWARD_H

#include "base/RefCount.h"

class ACL;
class ACLChecklist;
class ACLFilledChecklist;

class AclDenyInfoList;
class AclSizeLimit;

namespace Acl
{

class Address;
class Answer;
class InnerNode;
class NotNode;
class AndNode;
class OrNode;
class Tree;
class DirectiveRules;

using TreePointer = RefCount<Acl::Tree>;

/// prepares to parse ACLs configuration
void Init(void);

} // namespace Acl

typedef void ACLCB(Acl::Answer, void *);

#define ACL_NAME_SZ 64

// deprecated legacy names; use Acl::DirectiveRules instead
using acl_access = Acl::DirectiveRules;
using ACLList = Acl::DirectiveRules;

// XXX: Move into Acl::NamedRules after migrating to master commit 2e6535a
class AclNamedRules;

class ExternalACLEntry;
typedef RefCount<ExternalACLEntry> ExternalACLEntryPointer;
using ACLPointer = RefCount<ACL>; // XXX: move into Acl; rename or perhaps even remove

#endif /* SQUID_ACL_FORWARD_H */

