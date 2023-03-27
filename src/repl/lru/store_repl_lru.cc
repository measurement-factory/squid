/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: none          LRU Removal Policy */

#include "squid.h"
#include "MemObject.h"
#include "Store.h"

REMOVALPOLICYCREATE createRemovalPolicy_lru;

struct LruPolicyData {
    RemovalPolicyNode *getPolicyNode(StoreEntry *) const;
    RemovalPolicy *policy;
    dlink_list list;
    int count;
    int nwalkers;
    enum heap_entry_type {
        TYPE_UNKNOWN = 0, TYPE_STORE_ENTRY, TYPE_STORE_MEM
    } type;
};

/* Hack to avoid having to remember the RemovalPolicyNode location.
 * Needed by the purge walker to clear the policy information
 */
static enum LruPolicyData::heap_entry_type
repl_guessType(StoreEntry * entry, RemovalPolicyNode * node)
{
    if (node == &entry->repl)
        return LruPolicyData::TYPE_STORE_ENTRY;

    if (entry->mem_obj && node == &entry->mem_obj->repl)
        return LruPolicyData::TYPE_STORE_MEM;

    fatal("Heap Replacement: Unknown StoreEntry node type");

    return LruPolicyData::TYPE_UNKNOWN;
}

RemovalPolicyNode *
LruPolicyData::getPolicyNode(StoreEntry *entry) const
{
    switch (type) {

    case TYPE_STORE_ENTRY:
        return &entry->repl;

    case TYPE_STORE_MEM:
        return &entry->mem_obj->repl;

    default:
        assert(0);
        return nullptr;
    }
}

class LruNode
{
    MEMPROXY_CLASS(LruNode);

public:
    /* Note: the dlink_node MUST be the first member of the LruNode
     * structure. This member is later pointer typecasted to LruNode *.
     */
    dlink_node node;
};

static int nr_lru_policies = 0;

static void
lru_add_to(StoreEntry * entry, RemovalPolicyNode * node, LruPolicyData *policyData)
{
    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL))
        return;

    assert(!node->data);

    LruNode *lru_node;
    node->data = lru_node = new LruNode;
    dlinkAddTail(entry, &lru_node->node, &policyData->list);
    policyData->count += 1;

    if (!policyData->type)
        policyData->type = repl_guessType(entry, node);
}

static void
lru_add(RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node)
{
    auto lru = entry->locked() ? (LruPolicyData *)policy->_dataBusy : (LruPolicyData *)policy->_dataIdle;
    lru_add_to(entry, node, lru);
}

static void
lru_remove_from(StoreEntry * entry, RemovalPolicyNode * node, LruPolicyData *policyData)
{
    auto lru_node = reinterpret_cast<LruNode *>(node->data);
    if (!lru_node)
        return;

    /*
     * It seems to be possible for an entry to exist in the hash
     * but not be in the LRU list, so check for that case rather
     * than suffer a NULL pointer access.
     */
    if (nullptr == lru_node->node.data)
        return;

    assert(lru_node->node.data == entry);

    node->data = nullptr;

    dlinkDelete(&lru_node->node, &policyData->list);

    delete lru_node;

    assert(policyData->count > 0);
    policyData->count -= 1;
}

static void
lru_remove(RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node)
{
    auto lru = entry->locked() ? (LruPolicyData *)policy->_dataBusy : (LruPolicyData *)policy->_dataIdle;
    lru_remove_from(entry, node, lru);
}

static void
lru_referenced(RemovalPolicy * policy, StoreEntry * entry,
               RemovalPolicyNode * node)
{
    auto lru = entry->locked() ? (LruPolicyData *)policy->_dataBusy : (LruPolicyData *)policy->_dataIdle;
    LruNode *lru_node = (LruNode *)node->data;

    if (!lru_node)
        return;

    dlinkDelete(&lru_node->node, &lru->list);

    dlinkAddTail((void *) entry, &lru_node->node, &lru->list);
}

static void
lru_locked(RemovalPolicy * policy, StoreEntry * entry,
               RemovalPolicyNode * node)
{
    auto lruIdle = (LruPolicyData *)policy->_dataIdle;
    auto lruBusy = (LruPolicyData *)policy->_dataBusy;

    LruNode *lru_node = (LruNode *)node->data;

    if (!lru_node)
        return;

    lru_remove_from(entry, node, lruIdle);;

    lru_add_to(entry, node, lruBusy);
}

static void
lru_unlocked(RemovalPolicy * policy, StoreEntry * entry,
               RemovalPolicyNode * node)
{
    auto lruIdle = (LruPolicyData *)policy->_dataIdle;
    auto lruBusy = (LruPolicyData *)policy->_dataBusy;

    LruNode *lru_node = (LruNode *)node->data;

    if (!lru_node)
        return;

    lru_remove_from(entry, node, lruBusy);

    lru_add_to(entry, node, lruIdle);
}

/** RemovalPolicyWalker **/

typedef struct _LruWalkData LruWalkData;

struct _LruWalkData {
    LruNode *current;
};

static const StoreEntry *
lru_walkNext(RemovalPolicyWalker * walker)
{
    auto lru_walk_idle = (LruWalkData *)walker->_dataIdle;
    auto lru_walk_busy = (LruWalkData *)walker->_dataBusy;
    LruNode *lru_node = lru_walk_idle->current;

    if (lru_node) {
        lru_walk_idle->current = (LruNode *) lru_node->node.next;
    } else {
        lru_node = lru_walk_busy->current;
        if (!lru_node)
            return nullptr;
        lru_walk_busy->current = (LruNode *) lru_node->node.next;
    }

    return (StoreEntry *) lru_node->node.data;
}

static void
lru_walkDone(RemovalPolicyWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    auto lruIdle = (LruPolicyData *)policy->_dataIdle;
    auto lruBusy = (LruPolicyData *)policy->_dataBusy;
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lruIdle->nwalkers > 0);
    assert(lruBusy->nwalkers > 0);
    lruIdle->nwalkers -= 1;
    lruBusy->nwalkers -= 1;
    safe_free(walker->_dataIdle);
    safe_free(walker->_dataBusy);
    delete walker;
}

static RemovalPolicyWalker *
lru_walkInit(RemovalPolicy * policy)
{
    auto lruIdle = (LruPolicyData *)policy->_dataIdle;
    auto lruBusy = (LruPolicyData *)policy->_dataBusy;
    RemovalPolicyWalker *walker;
    LruWalkData *lru_walk_idle;
    LruWalkData *lru_walk_busy;
    lruIdle->nwalkers += 1;
    lruBusy->nwalkers += 1;
    walker = new RemovalPolicyWalker;
    lru_walk_idle = (LruWalkData *)xcalloc(1, sizeof(*lru_walk_idle));
    lru_walk_busy = (LruWalkData *)xcalloc(1, sizeof(*lru_walk_busy));
    walker->_policy = policy;
    walker->_dataIdle = lru_walk_idle;
    walker->_dataBusy = lru_walk_busy;
    walker->Next = lru_walkNext;
    walker->Done = lru_walkDone;
    lru_walk_idle->current = (LruNode *)lruIdle->list.head;
    lru_walk_busy->current = (LruNode *)lruBusy->list.head;
    return walker;
}

/** RemovalPurgeWalker **/

typedef struct _LruPurgeData LruPurgeData;

struct _LruPurgeData {
    LruNode *current;
    LruNode *start;
};

static StoreEntry *
lru_purgeNext(RemovalPurgeWalker * walker)
{
    auto lru_walker = (LruPurgeData *)walker->_dataIdle;
    RemovalPolicy *policy = walker->_policy;
    auto lru = (LruPolicyData *)policy->_dataIdle;
    LruNode *lru_node;
    StoreEntry *entry;

    lru_node = lru_walker->current;

    if (!lru_node || walker->scanned >= walker->max_scan)
        return nullptr;

    walker->scanned += 1;

    lru_walker->current = (LruNode *) lru_node->node.next;

    if (lru_walker->current == lru_walker->start) {
        /* Last node found */
        lru_walker->current = nullptr;
    }

    entry = (StoreEntry *) lru_node->node.data;
    lru_remove_from(entry, lru->getPolicyNode(entry), lru);
    return entry;
}

static void
lru_purgeDone(RemovalPurgeWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    auto lru = (LruPolicyData *)policy->_dataIdle;
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers > 0);
    lru->nwalkers -= 1;
    safe_free(walker->_dataIdle);
    delete walker;
}

static RemovalPurgeWalker *
lru_purgeInit(RemovalPolicy * policy, int max_scan)
{
    auto lru = (LruPolicyData *)policy->_dataIdle;
    RemovalPurgeWalker *walker;
    LruPurgeData *lru_walk;
    lru->nwalkers += 1;
    walker = new RemovalPurgeWalker;
    lru_walk = (LruPurgeData *)xcalloc(1, sizeof(*lru_walk));
    walker->_policy = policy;
    walker->_dataIdle = lru_walk;
    walker->max_scan = max_scan;
    walker->Next = lru_purgeNext;
    walker->Done = lru_purgeDone;
    lru_walk->start = lru_walk->current = (LruNode *) lru->list.head;
    return walker;
}

static void
lru_stats(RemovalPolicy * policy, StoreEntry * sentry)
{
    auto lru = (LruPolicyData *)policy->_dataIdle;
    LruNode *lru_node = (LruNode *) lru->list.head;

    if (lru_node) {
        StoreEntry *entry = (StoreEntry *) lru_node->node.data;
        storeAppendPrintf(sentry, "LRU reference age: %.2f days\n", (double) (squid_curtime - entry->lastref) / (double) (24 * 60 * 60));
    }
}

static void
lru_free(RemovalPolicy * policy)
{
    auto lru = (LruPolicyData *)policy->_dataIdle;
    /* Make some verification of the policy state */
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers);
    assert(lru->count);
    safe_free(lru);
    lru = (LruPolicyData *)policy->_dataBusy;
    assert(lru->nwalkers);
    assert(lru->count);
    safe_free(lru);

    /* Ok, time to destroy this policy */
    memset(policy, 0, sizeof(*policy));
    delete policy;
}

RemovalPolicy *
createRemovalPolicy_lru(wordlist * args)
{
    RemovalPolicy *policy;
    /* no arguments expected or understood */
    assert(!args);

    /* Allocate the needed structures */
    auto lru_data_idle = (LruPolicyData *)xcalloc(1, sizeof(LruPolicyData));
    auto lru_data_busy = (LruPolicyData *)xcalloc(1, sizeof(LruPolicyData));

    policy = new RemovalPolicy;

    /* Initialize the URL data */
    lru_data_idle->policy = policy;
    lru_data_busy->policy = policy;

    /* Populate the policy structure */
    policy->_type = "lru";

    policy->_dataIdle = lru_data_idle;

    policy->_dataBusy = lru_data_busy;

    policy->Free = lru_free;

    policy->Add = lru_add;

    policy->Remove = lru_remove;

    policy->Referenced = lru_referenced;

    policy->Dereferenced = lru_referenced;

    policy->Locked = lru_locked;

    policy->Unlocked = lru_unlocked;

    policy->WalkInit = lru_walkInit;

    policy->PurgeInit = lru_purgeInit;

    policy->Stats = lru_stats;

    /* Increase policy usage count */
    nr_lru_policies += 0;

    return policy;
}

