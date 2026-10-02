/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_TREE_H
#define SQUID_SRC_ACL_TREE_H

#include "acl/Acl.h"
#include "acl/BoolOps.h"
#include "base/IoManip.h"
#include "cbdata.h"
#include "sbuf/Stream.h"

namespace Acl
{

/// An ORed set of rules at the top of the ACL expression tree with support for
/// optional rule actions.
class Tree: public OrNode
{
    MEMPROXY_CLASS(Tree);

public:
    /// Configuration text containing zero or more directive lines. Each
    /// directive is formed by the given prefix followed by the Tree-stored
    /// action and the corresponding access rule. Handles all the necessary
    /// formatting, including spaces and new lines. \sa ruleConfig()
    /// \prec prefix is not empty
    /// \returns empty string if the tree does not store any access rules
    ///
    /// the supplied converter maps action.kind to a string
    template <class ActionToStringConverter>
    SBuf directivesConfig(const SBuf &prefix, ActionToStringConverter) const;

    /// The `[!]aclname...` part of a single ACL-aware directive configuration
    /// line (i.e. space-separated acl names, each possibly prefixed with "!").
    /// This method is for code that uses a Tree object to store a single access
    /// rule. Use directivesConfig() for code that stores multiple access rules.
    /// \returns empty string if the tree does not store any access rules
    /// \sa PrintOptionalRule()
    SBuf ruleConfig() const;

    /// Returns the corresponding action after a successful tree match.
    Answer winningAction() const;

    /// what action to use if no nodes matched
    Answer lastAction() const;

    /// appends and takes control over the rule with a given action
    void add(Acl::Node *rule, const Answer &action);
    void add(Acl::Node *rule); ///< same as InnerNode::add()

protected:
    /// Acl::OrNode API
    bool bannedAction(ACLChecklist *, Nodes::const_iterator) const override;
    Answer actionAt(const Nodes::size_type pos) const;

    /// if not empty, contains actions corresponding to InnerNode::nodes
    typedef std::vector<Answer> Actions;
    Actions actions;
};

inline const char *
AllowOrDeny(const Answer &action)
{
    return action.allowed() ? "allow" : "deny";
}

template <class ActionToStringConverter>
inline SBuf
Tree::directivesConfig(const SBuf &prefix, const ActionToStringConverter converter) const
{
    Assure(!prefix.isEmpty());
    SBufStream os;
    Actions::const_iterator action = actions.begin();
    typedef Nodes::const_iterator NCI;
    for (NCI node = nodes.begin(); node != nodes.end(); ++node) {

        os << prefix;

        if (action != actions.end()) {
            const auto DefaultActString = "???"; // TODO: Assure(act) instead.
            const char *act = converter(*action);
            os << ' ' << (act ? act : DefaultActString);
            ++action;
        }

        os << AsList((*node)->dump()).prefixedBy(" ").delimitedBy(" ");

        os << '\n';
    }
    return os.buf();
}

} // namespace Acl

#endif /* SQUID_SRC_ACL_TREE_H */

