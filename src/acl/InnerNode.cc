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

void
Acl::InnerNode::syncReferences(const bool dryRun)
{
    debugs(28, 5, name << " with " << nodes.size() << " nodes");
    for (auto &node: nodes) {

        if (const auto newAcl = ACL::FindByName(node->name)) {
            debugs(28, (dryRun ? 7:5), "found " << node->name << ' ' << node << "=>" << newAcl);
            if (!dryRun)
                node = newAcl;
            continue;
        }

        if (const auto implicitAcl = dynamic_cast<InnerNode*>(node)) {
            debugs(28, 7, "stepping into implicit " << node->name);
            // these ACLs lack explicit "acl name..." lines and, hence, are not
            // registered as such; we cannot partially reconfigure them yet
            implicitAcl->syncReferences(dryRun);
            continue;
        }

        throw TextException(ToSBuf("cannot find and sync ACL ", node->name), Here());
    }
}

// one call parses one "acl name acltype name1 name2 ..." line
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
        if (negated)
            ++t;

        debugs(28, 3, "looking for ACL " << t);
        ACL *a = ACL::FindByName(t);

        if (a == NULL) {
            debugs(28, DBG_CRITICAL, "ACL not found: " << t);
            self_destruct();
            return;
        }

        // append(negated ? new NotNode(a) : a);
        if (negated)
            add(new NotNode(a));
        else
            add(a);
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

