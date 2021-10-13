/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_INNER_NODE_H
#define SQUID_ACL_INNER_NODE_H

#include "acl/Acl.h"
#include <vector>

namespace Acl
{

/// operands of a boolean ACL expression, in configuration/evaluation order
using Nodes = std::vector<ACL::Pointer>;

/// An intermediate ACL tree node. Manages a collection of child tree nodes.
class InnerNode: public ACL
{
public:
    /// Resumes matching (suspended by an async call) at the given position.
    bool resumeMatchingAt(ACLChecklist *checklist, Acl::Nodes::const_iterator pos) const;

    /// the number of children nodes
    Nodes::size_type childrenCount() const { return nodes.size(); }

    /* ACL API */
    virtual void prepareForUse();
    virtual bool empty() const;
    virtual SBufList dump() const;

    /// parses a [ [!]acl1 [!]acl2... ] sequence, appending to nodes
    /// \returns the number of parsed ACL names
    size_t lineParse();

    /// appends the node to the collection and takes control over it
    void add(ACL *node);

    /// recreate the same InnerNode ACL using up-to-date nodes
    InnerNode *makeSyncedVersion() const;

protected:
    /// a fresh/post-reconfiguration version of the given [stale] ACL
    /// \returns either an existing ACL object or a newly created ACL object
    static ACL *SyncedVersionOf(const ACL &);

    /// fills the given node with synced versions of our nodes and other details
    virtual void fillToSync(InnerNode &) const;

    /// Creates an ACL object with the C++ type of the method implementer.
    /// The returned object is meant to be filled/configured using fillToSync().
    virtual InnerNode *newToSync() const = 0;

    /// checks whether the nodes match, starting with the given one
    /// kids determine what a match means for their type of intermediate nodes
    virtual int doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const = 0;

    /* ACL API */
    virtual int match(ACLChecklist *checklist);

    Nodes nodes; ///< children of this intermediate node
};

} // namespace Acl

#endif /* SQUID_ACL_INNER_NODE_H */

