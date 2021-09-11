/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 28    Access Control
 *
 * This file contains ACL routines that are not part of the
 * ACL class, nor any other class yet, and that need to be
 * factored into appropriate places. They are here to reduce
 * unneeded dependencies between the ACL class and the rest
 * of squid.
 */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/AclDenyInfoList.h"
#include "acl/Checklist.h"
#include "acl/DirectiveRules.h"
#include "acl/Gadgets.h"
#include "acl/Strategised.h"
#include "acl/Tree.h"
#include "ConfigParser.h"
#include "errorpage.h"
#include "globals.h"
#include "HttpRequest.h"
#include "src/sbuf/Stream.h"

#include <deque>
#include <algorithm>

/* does name lookup, returns page_id */
err_type
aclGetDenyInfoPage(AclDenyInfoList ** head, const char *name, int redirect_allowed)
{
    if (!name) {
        debugs(28, 3, "ERR_NONE due to a NULL name");
        return ERR_NONE;
    }

    AclDenyInfoList *A = NULL;

    debugs(28, 8, HERE << "got called for " << name);

    for (A = *head; A; A = A->next) {
        if (!redirect_allowed && strchr(A->err_page_name, ':') ) {
            debugs(28, 8, HERE << "Skip '" << A->err_page_name << "' 30x redirects not allowed as response here.");
            continue;
        }

        for (const auto &aclName: A->acl_list) {
            if (aclName.cmp(name) == 0) {
                debugs(28, 8, "match on " << name);
                return A->err_page_id;
            }
        }
    }

    debugs(28, 8, "aclGetDenyInfoPage: no match");
    return ERR_NONE;
}

/* does name lookup, returns if it is a proxy_auth acl */
int
aclIsProxyAuth(const char *name)
{
    if (!name) {
        debugs(28, 3, "false due to a NULL name");
        return false;
    }

    debugs(28, 5, "aclIsProxyAuth: called for " << name);

    ACL *a;

    if ((a = ACL::FindByName(name))) {
        debugs(28, 5, "aclIsProxyAuth: returning " << a->isProxyAuth());
        return a->isProxyAuth();
    }

    debugs(28, 3, "aclIsProxyAuth: WARNING, called for nonexistent ACL");
    return false;
}

/* maex@space.net (05.09.96)
 *    get the info for redirecting "access denied" to info pages
 *      TODO (probably ;-)
 *      currently there is no optimization for
 *      - more than one deny_info line with the same url
 *      - a check, whether the given acl really is defined
 *      - a check, whether an acl is added more than once for the same url
 */

void
aclParseDenyInfoLine(AclDenyInfoList ** head)
{
    char *t = NULL;
    AclDenyInfoList *B;
    AclDenyInfoList **T;

    /* first expect a page name */

    if ((t = ConfigParser::NextToken()) == NULL) {
        debugs(28, DBG_CRITICAL, "aclParseDenyInfoLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseDenyInfoLine: missing 'error page' parameter.");
        return;
    }

    const auto A = new AclDenyInfoList(t, ConfigParser::CurrentLocation());

    /* next expect a list of ACL names */
    while ((t = ConfigParser::NextToken())) {
        A->acl_list.emplace_back(t);
    }

    if (A->acl_list.empty()) {
        debugs(28, DBG_CRITICAL, "aclParseDenyInfoLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseDenyInfoLine: deny_info line contains no ACL's, skipping");
        delete A;
        return;
    }

    for (B = *head, T = head; B; T = &B->next, B = B->next)

        ;   /* find the tail */
    *T = A;
}

void
aclParseAccessLine(const char *directive, ConfigParser &, acl_access **configPtr)
{
    /* first expect either 'allow' or 'deny' */
    const char *t = ConfigParser::NextToken();

    if (!t) {
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: missing 'allow' or 'deny'.");
        return;
    }

    auto action = Acl::Answer(ACCESS_DUNNO);
    if (!strcmp(t, "allow"))
        action = Acl::Answer(ACCESS_ALLOWED);
    else if (!strcmp(t, "deny"))
        action = Acl::Answer(ACCESS_DENIED);
    else {
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: expecting 'allow' or 'deny', got '" << t << "'.");
        return;
    }

    assert(configPtr);
    auto &config = *configPtr;
    const int ruleId = (config ? config->raw->childrenCount() : 0) + 1;
    MemBuf ctxBuf;
    ctxBuf.init();
    ctxBuf.appendf("%s#%d", directive, ruleId);
    ctxBuf.terminate();

    Acl::AndNode *rule = new Acl::AndNode;
    rule->context(ctxBuf.content(), config_input_line);
    rule->lineParse();
    if (rule->empty()) {
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "aclParseAccessLine: Access line contains no ACL's, skipping");
        delete rule;
        return;
    }

    /* Append to the end of this list */

    if (!config)
        config = new Acl::DirectiveRules(directive, config_input_line);

    config->raw->add(rule, action);
}

// aclParseAclList does not expect or set actions (cf. aclParseAccessLine)
void
aclParseAclList(ConfigParser &parser, ACLList **configPtr, const char *label)
{
    // accommodate callers unable to convert their ACL list context to string
    if (!label)
        label = "...";

    MemBuf ctxLine;
    ctxLine.init();
    ctxLine.appendf("(%s %s line)", cfg_directive, label);
    ctxLine.terminate();

    // TODO: Refactor Acl::Tree so that it can also be an AndNode and then
    // optimize by merging config->raw and this rule into an ACL tree root.
    Acl::AndNode *rule = new Acl::AndNode;
    rule->context(ctxLine.content(), config_input_line);
    rule->lineParse();

    MemBuf ctxTree;
    ctxTree.init();
    ctxTree.appendf("%s %s", cfg_directive, label);
    ctxTree.terminate();

    assert(configPtr);
    auto &config = *configPtr;
    assert(!config);
    config = new Acl::DirectiveRules(ctxTree.content(), config_input_line);
    config->raw->add(rule);
}

/*********************/
/* Destroy functions */
/*********************/

void
aclDestroyAclList(ACLList **list)
{
    debugs(28, 8, "aclDestroyAclList: invoked");
    assert(list);
    delete *list; // XXX
    *list = NULL;
}

void
aclDestroyAccessList(acl_access **config)
{
    assert(config);
    if (const auto list = *config) {
        debugs(28, 3, "destroying: " << list->raw << ' ' << list->raw->name);
        delete list; // XXX
        *config = nullptr;
    }
}

/* maex@space.net (06.09.1996)
 *    destroy an AclDenyInfoList */

void
aclDestroyDenyInfoList(AclDenyInfoList ** list)
{
    AclDenyInfoList *a = NULL;
    AclDenyInfoList *a_next = NULL;

    debugs(28, 8, "aclDestroyDenyInfoList: invoked");

    for (a = *list; a; a = a_next) {
        a_next = a->next;
        delete a;
    }

    *list = NULL;
}

