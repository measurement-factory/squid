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
#include "cbdata.h"
#include "sbuf/List.h"

namespace Acl
{

/// An ORed set of rules at the top of the ACL expression tree with support for
/// optional rule actions.
class Tree: public OrNode
{
    MEMPROXY_CLASS(Tree);

public:
    /// The list of tokens, spaces, and new lines that, if concatenated, produce
    /// a valid configuration text containing zero or more directive lines. Each
    /// directive is formed by the given prefix followed by the Tree-stored
    /// action and the corresponding access rule. Handles all the necessary
    /// formatting, including spaces and new lines. \sa ruleDump()
    ///
    /// the supplied converter maps action.kind to a string
    template <class ActionToStringConverter>
    SBufList treeDump(const SBuf &prefix, ActionToStringConverter) const;

    /// treeDump(SBuf, ...) wrapper for legacy callers. TODO: Remove this diff reducer.
    template <class ActionToStringConverter>
    SBufList treeDump(const char * const prefix, const ActionToStringConverter action) const { return treeDump(SBuf(prefix), action); }

    /// The list of acl names, each possibly prefixed with "!" (e.g., words that
    /// follow an `http_access allow` directive line prefix). This method is for
    /// code that uses a Tree object to store a single access rule. Code that
    /// stores multiple access rules must use treeDump() instead.
    SBufList ruleDump() const;

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
inline SBufList
Tree::treeDump(const SBuf &prefix, const ActionToStringConverter converter) const
{
    SBufList text;
    Actions::const_iterator action = actions.begin();
    typedef Nodes::const_iterator NCI;
    for (NCI node = nodes.begin(); node != nodes.end(); ++node) {

        // number of words added to the current directive line
        size_t wordCount = 0;

        const auto addWord = [&text,&wordCount](const SBuf &word) {
            if (wordCount++) {
                static const auto space = SBuf(" ");
                text.push_back(space);
            }
            text.push_back(word);
        };

        addWord(prefix);

        if (action != actions.end()) {
            static const SBuf DefaultActString("???");
            const char *act = converter(*action);
            addWord(act ? SBuf(act) : DefaultActString);
            ++action;
        }

        for (const auto &word: (*node)->dump()) {
            addWord(word);
        }

        static const auto nl = SBuf("\n");
        text.push_back(nl);
    }
    return text;
}

} // namespace Acl

#endif /* SQUID_SRC_ACL_TREE_H */

