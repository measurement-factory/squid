/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
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

static LruPolicyData *
PolicyData(RemovalPolicy *policy, const StoreEntry *e) {
    return static_cast<LruPolicyData *>(e->locked() ? policy->_dataBusy : policy->_dataIdle);
}

static LruPolicyData *
DataIdle(RemovalPolicy *policy) { return static_cast<LruPolicyData *>(policy->_dataIdle); }

static LruPolicyData *
DataBusy(RemovalPolicy *policy) { return static_cast<LruPolicyData *>(policy->_dataBusy); }

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
lru_add_to(StoreEntry *entry, RemovalPolicyNode *node, LruPolicyData *policyData)
{
    assert(!node->data);

    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL))
        return;

    auto lru_node = new LruNode;
    node->data = lru_node;
    dlinkAddTail(entry, &lru_node->node, &policyData->list);
    policyData->count += 1;

    if (!policyData->type)
        policyData->type = repl_guessType(entry, node);
}

static void
lru_add(RemovalPolicy *policy, StoreEntry *entry, RemovalPolicyNode *node)
{
    lru_add_to(entry, node, PolicyData(policy, entry));
}

static void
lru_remove_from(StoreEntry *entry, RemovalPolicyNode *node, LruPolicyData *policyData)
{
    auto lru_node = static_cast<LruNode *>(node->data);
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
    lru_remove_from(entry, node, PolicyData(policy, entry));
}

static void
lru_referenced(RemovalPolicy * policy, const StoreEntry * entry,
               RemovalPolicyNode * node)
{
    auto lru = PolicyData(policy, entry);
    if (auto lru_node = static_cast<LruNode *>(node->data)) {
        dlinkDelete(&lru_node->node, &lru->list);
        dlinkAddTail(const_cast<StoreEntry*>(entry), &lru_node->node, &lru->list);
    }
}

static void
lru_locked(RemovalPolicy *policy, StoreEntry *entry, RemovalPolicyNode *node)
{
    if (node->data) {
        lru_remove_from(entry, node, DataIdle(policy));
        lru_add_to(entry, node, DataBusy(policy));
    }
}

static void
lru_unlocked(RemovalPolicy *policy, StoreEntry *entry, RemovalPolicyNode *node)
{
    if (node->data) {
        lru_remove_from(entry, node, DataBusy(policy));
        lru_add_to(entry, node, DataIdle(policy));
    }
}

/** RemovalPolicyWalker **/

typedef struct _LruWalkData LruWalkData;

struct _LruWalkData {
    LruNode *current;
};

static const StoreEntry *
lru_walkNext(RemovalPolicyWalker * walker)
{
    auto walkIdle = static_cast<LruWalkData *>(walker->_dataIdle);
    auto walkBusy = static_cast<LruWalkData *>(walker->_dataBusy);
    auto lru_node = walkIdle->current;

    if (lru_node) {
        walkIdle->current = reinterpret_cast<LruNode *>(lru_node->node.next);
    } else {
        lru_node = walkBusy->current;
        if (!lru_node)
            return nullptr;
        walkBusy->current = reinterpret_cast<LruNode *>(lru_node->node.next);
    }

    return static_cast<StoreEntry *>(lru_node->node.data);
}

static void
lru_walkDone(RemovalPolicyWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    assert(strcmp(policy->_type, "lru") == 0);

    auto lruIdle = DataIdle(policy);
    assert(lruIdle->nwalkers > 0);
    lruIdle->nwalkers -= 1;
    safe_free(walker->_dataIdle);

    auto lruBusy = DataBusy(policy);
    assert(lruBusy->nwalkers > 0);
    lruBusy->nwalkers -= 1;
    safe_free(walker->_dataBusy);

    delete walker;
}

static RemovalPolicyWalker *
lru_walkInit(RemovalPolicy * policy)
{
    auto lruIdle = DataIdle(policy);
    lruIdle->nwalkers += 1;

    auto lruBusy = DataBusy(policy);
    lruBusy->nwalkers += 1;

    auto lru_walk_idle = static_cast<LruWalkData *>(xcalloc(1, sizeof(LruWalkData)));
    auto lru_walk_busy = static_cast<LruWalkData *>(xcalloc(1, sizeof(LruWalkData)));

    auto walker = new RemovalPolicyWalker;
    walker->_policy = policy;
    walker->_dataIdle = lru_walk_idle;
    walker->_dataBusy = lru_walk_busy;
    walker->Next = lru_walkNext;
    walker->Done = lru_walkDone;
    lru_walk_idle->current = reinterpret_cast<LruNode *>(lruIdle->list.head);
    lru_walk_busy->current = reinterpret_cast<LruNode *>(lruBusy->list.head);
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
    auto lru_walker = static_cast<LruPurgeData *>(walker->_dataIdle);
    auto lru_node = lru_walker->current;

    if (!lru_node || walker->scanned >= walker->max_scan)
        return nullptr;

    walker->scanned += 1;

    lru_walker->current = reinterpret_cast<LruNode *>(lru_node->node.next);

    if (lru_walker->current == lru_walker->start) {
        /* Last node found */
        lru_walker->current = nullptr;
    }

    auto entry = static_cast<StoreEntry *>(lru_node->node.data);
    auto lru = DataIdle(walker->_policy);
    auto policyNode = lru->getPolicyNode(entry);
    assert(policyNode);
    lru_remove_from(entry, policyNode, lru);
    return entry;
}

static void
lru_purgeDone(RemovalPurgeWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    auto lru = DataIdle(policy);
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers > 0);
    lru->nwalkers -= 1;
    safe_free(walker->_dataIdle);
    delete walker;
}

static RemovalPurgeWalker *
lru_purgeInit(RemovalPolicy * policy, int max_scan)
{
    auto lru = DataIdle(policy);
    lru->nwalkers += 1;
    auto walker = new RemovalPurgeWalker;
    auto lru_walk = static_cast<LruPurgeData *>(xcalloc(1, sizeof(LruPurgeData)));
    walker->_policy = policy;
    walker->_dataIdle = lru_walk;
    walker->max_scan = max_scan;
    walker->Next = lru_purgeNext;
    walker->Done = lru_purgeDone;
    lru_walk->start = lru_walk->current = reinterpret_cast<LruNode *>(lru->list.head);
    return walker;
}

static void
lru_stats(RemovalPolicy * policy, StoreEntry * sentry)
{
    if (auto lru_node = reinterpret_cast<LruNode *>(DataIdle(policy)->list.head)) {
        auto entry = static_cast<StoreEntry *>(lru_node->node.data);
        storeAppendPrintf(sentry, "LRU reference age: %.2f days\n", (double) (squid_curtime - entry->lastref) / (double) (24 * 60 * 60));
    }
}

static void
lru_free(RemovalPolicy * policy)
{
    auto lru = DataIdle(policy);
    /* Make some verification of the policy state */
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers);
    assert(lru->count);
    safe_free(lru);
    lru = DataBusy(policy);
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
    /* no arguments expected or understood */
    assert(!args);

    /* Allocate the needed structures */
    auto dataIdle = static_cast<LruPolicyData *>(xcalloc(1, sizeof(LruPolicyData)));
    auto dataBusy = static_cast<LruPolicyData *>(xcalloc(1, sizeof(LruPolicyData)));

    auto policy = new RemovalPolicy;

    /* Initialize the URL data */
    dataIdle->policy = policy;
    dataBusy->policy = policy;

    /* Populate the policy structure */
    policy->_type = "lru";

    policy->_dataIdle = dataIdle;

    policy->_dataBusy = dataBusy;

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

