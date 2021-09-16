/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/BoolOps.h"
#include "acl/Checklist.h"
#include "acl/Gadgets.h"
#include "acl/InnerNode.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "globals.h"
#include "sbuf/Stream.h"

#include <algorithm>
#include <memory>

void
Acl::InnerNode::prepareForUse()
{
    for (auto node : nodes)
        node->prepareForUse();
}

bool
Acl::InnerNode::empty() const
{
    return nodes.empty();
}

void
Acl::InnerNode::add(ACL *node)
{
    assert(node != NULL);
    nodes.push_back(node);
}

ACL *
Acl::InnerNode::SyncedVersionOf(const ACL &staleAcl)
{
    if (const auto freshAcl = ACL::FindByName(staleAcl.name)) {
        debugs(28, 7, "found " << staleAcl.name << ' ' << &staleAcl << "=>" << freshAcl);
        return freshAcl;
    }

    if (const auto implicitAcl = dynamic_cast<const Acl::InnerNode*>(&staleAcl)) {
        debugs(28, 7, "stepping into implicit " << staleAcl.name);
        return implicitAcl->makeSyncedVersion();
    }

    throw TextException(ToSBuf("cannot find and sync ACL ", staleAcl.name), Here());
}

Acl::InnerNode *
Acl::InnerNode::makeSyncedVersion() const
{
    std::unique_ptr<InnerNode> newMe(newToSync());
    fillToSync(*newMe);
    return newMe.release();
}

void
Acl::InnerNode::fillToSync(InnerNode &newMe) const
{
    debugs(28, 5, name << " with " << nodes.size() << " nodes");
    assert(this != &newMe);
    newMe.context(name, cfgline);
    for (const auto &staleNode: nodes)
        newMe.add(SyncedVersionOf(*staleNode));
}

// one call parses one "aclName1 aclName2 ..." sequence
// kids use this method to handle [multiple] parse() calls correctly
void
Acl::InnerNode::lineParse()
{
    // XXX: not precise, may change when looping or parsing multiple lines
    if (!cfgline)
        cfgline = xstrdup(config_input_line);

    // expect a list of ACL names, each possibly preceded by '!' for negation

    while (const char *t = ConfigParser::strtokFile()) {
        const bool negated = (*t == '!');
        const auto aclName = negated ? t+1 : t;

        const auto a = ACL::FindByName(aclName);

        if (a == NULL) {
            debugs(28, DBG_CRITICAL, "ERROR: Cannot find ACL named " << aclName);
            self_destruct();
            return;
        }

        if (negated) {
            const auto negatingNode = new NotNode();
            negatingNode->context(t, cfgline);
            negatingNode->add(a);
            add(negatingNode);
        } else {
            add(a);
        }
    }

    return;
}

SBufList
Acl::InnerNode::dump() const
{
    SBufList rv;
    for (Nodes::const_iterator i = nodes.begin(); i != nodes.end(); ++i)
        rv.push_back(SBuf((*i)->name));
    return rv;
}

int
Acl::InnerNode::match(ACLChecklist *checklist)
{
    return doMatch(checklist, nodes.begin());
}

bool
Acl::InnerNode::resumeMatchingAt(ACLChecklist *checklist, Acl::Nodes::const_iterator pos) const
{
    debugs(28, 5, "checking " << name << " at " << (pos-nodes.begin()));
    const int result = doMatch(checklist, pos);
    const char *extra = checklist->asyncInProgress() ? " async" : "";
    debugs(28, 3, "checked: " << name << " = " << result << extra);

    // merges async and failures (-1) into "not matched"
    return result == 1;
}

