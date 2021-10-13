/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
class AndNode;
class Answer;
class ChecklistFiller;
class InnerNode;
class NotNode;
class OrNode;
class Tree;

using TreePointer = RefCount<Acl::Tree>;

/// prepares to parse ACLs configuration
void Init(void);

} // namespace Acl

typedef void ACLCB(Acl::Answer, void *);

#define ACL_NAME_SZ 64

/// deprecated; use Acl::TreePointer directly
class acl_access {
public:
    RefCount<Acl::Tree> raw;
};
/// deprecated; use Acl::TreePointer directly
using ACLList = acl_access;

// XXX: Move into Acl::NamedRules after migrating to master commit 2e6535a
class AclNamedRules;

class ExternalACLEntry;
typedef RefCount<ExternalACLEntry> ExternalACLEntryPointer;
using ACLPointer = RefCount<ACL>; // XXX: move into Acl; rename or perhaps even remove

#endif /* SQUID_ACL_FORWARD_H */

