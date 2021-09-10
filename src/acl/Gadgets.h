/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_GADGETS_H
#define SQUID_ACL_GADGETS_H

#include "acl/forward.h"
#include "error/forward.h"

#include <sstream>

class ConfigParser;
class dlink_list;
class StoreEntry;
class wordlist;

namespace Acl {
    // TODO: Enable or remove.
    /// Makes the given rules inaccessible; deletes unused rules
    //void Forget(PermissionTreePointer&);
}

/// Acl::Forget() wrapper used by legacy code
void aclDestroyAccessList(acl_access **list);
/// Acl::Forget() wrapper used by legacy code
void aclDestroyAclList(ACLList**);
//void aclDestroyAclList(Acl::PermissionTreePointer *); // XXX: half-way wrapper
/// Acl::Forget() wrapper used by legacy code
void aclDestroyAccessList(acl_access **list);

/// Parses a single line of a "action followed by acls" directive (e.g., http_access).
void aclParseAccessLine(const char *directive, ConfigParser &parser, acl_access **);
/// parseAcls() wrapper used by legacy code
void aclParseAclList(ConfigParser &parser, ACLList **, const char *label);


namespace Acl {

// XXX: Revise new names

// /// Parses a single line of a "action followed by acls" directive (e.g., http_access).
// void parseActionAcls(const char *directive, ConfigParser &, ActionTreePointer &);

// /// Parses a single line of a "some context followed by acls" directive (e.g., note n v).
// /// The label parameter identifies the context (for debugging).
// void parseAcls(ConfigParser &parser, Acl::PermissionTreePointer &, const char *label);

// /// parseAcls() convenience wrapper; converts any context info into a c-string.
// template <class Any>
// inline
// void parseAclsFor(ConfigParser &parser, Acl::PermissionTreePointer &tree, const Any any)
// {
//     std::ostringstream buf;
//     buf << any;
//     parseAcls(parser, tree, buf.str().c_str());
// }

} // namespace Acl

template <class Any>
void aclParseAclList(ConfigParser &parser, ACLList **tree, const Any any)
{
    std::ostringstream buf;
    buf << any;
    aclParseAclList(parser, tree, buf.str().c_str());
}

/// \ingroup ACLAPI
int aclIsProxyAuth(const char *name);
/// \ingroup ACLAPI
err_type aclGetDenyInfoPage(AclDenyInfoList ** head, const char *name, int redirect_allowed);
/// \ingroup ACLAPI
void aclParseDenyInfoLine(AclDenyInfoList **);
/// \ingroup ACLAPI
void aclDestroyDenyInfoList(AclDenyInfoList **);
/// \ingroup ACLAPI
wordlist *aclDumpGeneric(const ACL *);
/// \ingroup ACLAPI
void aclCacheMatchFlush(dlink_list * cache);
/// \ingroup ACLAPI
void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head);
/// \ingroup ACLAPI
void dump_acl_list(StoreEntry * entry, ACLList * head);
// XXX: half-way wrapper
// void dump_acl_access(StoreEntry * entry, const char *name, const Acl::PermissionTreePointer &);

#endif /* SQUID_ACL_GADGETS_H */

