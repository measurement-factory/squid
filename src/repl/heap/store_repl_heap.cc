/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 81    Store HEAP Removal Policies
 *
 * Based on the ideas of the heap policy implemented by John Dilley of
 * Hewlett Packard. Rewritten from scratch when modularizing the removal
 * policy implementation of Squid.
 *
 * For details on the original heap policy work and the thinking behind see
 * http://www.hpl.hp.com/techreports/1999/HPL-1999-69.html
 */

#include "squid.h"
#include "heap.h"
#include "MemObject.h"
#include "Store.h"
#include "store_heap_replacement.h"
#include "wordlist.h"

#include <queue>

REMOVALPOLICYCREATE createRemovalPolicy_heap;

static int nr_heap_policies = 0;

struct HeapPolicyData {
    void resetPolicyNode(StoreEntry *) const;
    RemovalPolicy *policy;
    heap *theHeap;
    heap_key_func *keyfunc;
    int count;
    int nwalkers;
    enum heap_entry_type {
        TYPE_UNKNOWN = 0, TYPE_STORE_ENTRY, TYPE_STORE_MEM
    } type;
};

static HeapPolicyData *
PolicyData(RemovalPolicy *policy, StoreEntry *e) {
    return reinterpret_cast<HeapPolicyData *>(e->locked() ? policy->_dataBusy : policy->_dataIdle);
}

static HeapPolicyData *
DataIdle(RemovalPolicy *policy) { return reinterpret_cast<HeapPolicyData *>(policy->_dataIdle); }

static HeapPolicyData *
DataBusy(RemovalPolicy *policy) { return reinterpret_cast<HeapPolicyData *>(policy->_dataBusy); }

/* Hack to avoid having to remember the RemovalPolicyNode location.
 * Needed by the purge walker.
 */
static enum HeapPolicyData::heap_entry_type
heap_guessType(StoreEntry * entry, RemovalPolicyNode * node)
{
    if (node == &entry->repl)
        return HeapPolicyData::TYPE_STORE_ENTRY;

    if (entry->mem_obj && node == &entry->mem_obj->repl)
        return HeapPolicyData::TYPE_STORE_MEM;

    fatal("Heap Replacement: Unknown StoreEntry node type");

    return HeapPolicyData::TYPE_UNKNOWN;
}

void
HeapPolicyData::resetPolicyNode(StoreEntry *entry) const
{
    RemovalPolicyNode *node = nullptr;
    switch (type) {

    case TYPE_STORE_ENTRY:
        node = &entry->repl;
        break ;

    case TYPE_STORE_MEM:
        node = &entry->mem_obj->repl;
        break ;

    default:
        break;
    }
    assert(node);
    node->data = nullptr;
}

static void
heap_add_to(StoreEntry *entry, RemovalPolicyNode *node, HeapPolicyData *policyData)
{
    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL))
        return;         /* We won't manage these.. they messes things up */

    assert(!node->data);

    node->data = heap_insert(policyData->theHeap, entry);

    policyData->count += 1;

    if (!policyData->type)
        policyData->type = heap_guessType(entry, node);

    /* Add a little more variance to the aging factor */
    policyData->theHeap->age += policyData->theHeap->age / 100000000;
}

static void
heap_add(RemovalPolicy *policy, StoreEntry *entry, RemovalPolicyNode *node)
{
    heap_add_to(entry, node, PolicyData(policy, entry));
}

static void
heap_remove_from(RemovalPolicyNode *node, HeapPolicyData *policyData)
{
    if (auto hnode = reinterpret_cast<heap_node *>(node->data)) {
        heap_delete(policyData->theHeap, hnode);
        node->data = nullptr;
        assert(policyData->count > 0);
        policyData->count -= 1;
    }
}

static void
heap_remove(RemovalPolicy * policy, StoreEntry *e,
            RemovalPolicyNode * node)
{
    heap_remove_from(node, PolicyData(policy, e));
}

static void
heap_referenced(RemovalPolicy * policy, StoreEntry * entry,
                RemovalPolicyNode * node)
{
    if (auto hnode = reinterpret_cast<heap_node *>(node->data))
        heap_update(PolicyData(policy, entry)->theHeap, hnode, entry);
}

static void
heap_locked(RemovalPolicy * policy, StoreEntry * entry,
                RemovalPolicyNode * node)
{
    if (node->data) {
        heap_remove_from(node, DataIdle(policy));
        heap_add_to(entry, node, DataBusy(policy));
    }
}

static void
heap_unlocked(RemovalPolicy * policy, StoreEntry * entry,
                RemovalPolicyNode * node)
{
    if (node->data) {
        heap_remove_from(node, DataBusy(policy));
        heap_add_to(entry, node, DataIdle(policy));
    }
}

/** RemovalPolicyWalker **/

typedef struct _HeapWalkData HeapWalkData;

struct _HeapWalkData {
    size_t current;
};

static const StoreEntry *
heap_walkNext(RemovalPolicyWalker * walker)
{
    auto hIdle = reinterpret_cast<HeapWalkData *>(walker->_dataIdle);
    auto hBusy = reinterpret_cast<HeapWalkData *>(walker->_dataBusy);
    auto policy = walker->_policy;
    auto dataIdle = DataIdle(policy);
    auto dataBusy = DataBusy(policy);

    if (hIdle->current < heap_nodes(dataIdle->theHeap))
        return (StoreEntry *)heap_peep(dataIdle->theHeap, hIdle->current++);
    if (hBusy->current < heap_nodes(dataBusy->theHeap))
        return (StoreEntry *)heap_peep(dataBusy->theHeap, hBusy->current++);
    return nullptr;
}

static void
heap_walkDone(RemovalPolicyWalker * walker)
{
    auto policy = walker->_policy;
    auto dataIdle = DataIdle(policy);
    auto dataBusy = DataBusy(policy);
    assert(strcmp(policy->_type, "heap") == 0);
    assert(dataIdle->nwalkers > 0);
    assert(dataBusy->nwalkers > 0);
    dataIdle->nwalkers -= 1;
    dataBusy->nwalkers -= 1;
    safe_free(walker->_dataIdle);
    safe_free(walker->_dataBusy);
    delete walker;
}

static RemovalPolicyWalker *
heap_walkInit(RemovalPolicy * policy)
{
    DataIdle(policy)->nwalkers += 1;
    DataBusy(policy)->nwalkers += 1;
    auto walker = new RemovalPolicyWalker;
    auto dataIdle = reinterpret_cast<HeapWalkData *>(xcalloc(1, sizeof(HeapWalkData)));
    dataIdle->current = 0;
    auto dataBusy = reinterpret_cast<HeapWalkData *>(xcalloc(1, sizeof(HeapWalkData)));
    dataBusy->current = 0;
    walker->_policy = policy;
    walker->_dataIdle = dataIdle;
    walker->_dataBusy = dataBusy;
    walker->Next = heap_walkNext;
    walker->Done = heap_walkDone;
    return walker;
}

/** RemovalPurgeWalker **/

class HeapPurgeData
{
public:
    std::queue<StoreEntry *> locked_entries;
    heap_key min_age = 0.0;
};

static StoreEntry *
heap_purgeNext(RemovalPurgeWalker * walker)
{
    auto heap_walker = reinterpret_cast<HeapPurgeData *>(walker->_dataIdle);
    auto policy = walker->_policy;
    auto data = DataIdle(policy);

    if (heap_empty(data->theHeap))
        return nullptr;        /* done */

    const auto age = heap_peepminkey(data->theHeap);

    auto entry = reinterpret_cast<StoreEntry *>(heap_extractmin(data->theHeap));

    heap_walker->min_age = age;
    data->resetPolicyNode(entry);
    return entry;
}

static void
heap_purgeDone(RemovalPurgeWalker * walker)
{
    auto heap_walker = reinterpret_cast<HeapPurgeData *>(walker->_dataIdle);
    auto policy = walker->_policy;
    auto data = DataIdle(policy);
    assert(strcmp(policy->_type, "heap") == 0);
    assert(data->nwalkers > 0);
    data->nwalkers -= 1;

    if (heap_walker->min_age > 0) {
        data->theHeap->age = heap_walker->min_age;
        debugs(81, 3, "Heap age set to " << data->theHeap->age);
    }

    delete heap_walker;
    delete walker;
}

static RemovalPurgeWalker *
heap_purgeInit(RemovalPolicy * policy, int max_scan)
{
    DataIdle(policy)->nwalkers += 1;
    auto walker = new RemovalPurgeWalker;
    auto heap_walk = new HeapPurgeData;
    walker->_policy = policy;
    walker->_dataIdle = heap_walk;
    walker->max_scan = max_scan;
    walker->Next = heap_purgeNext;
    walker->Done = heap_purgeDone;
    return walker;
}

static void
heap_free(RemovalPolicy * policy)
{
    auto data = DataIdle(policy);
    /* Make some verification of the policy state */
    assert(strcmp(policy->_type, "heap") == 0);
    assert(data->nwalkers);
    assert(data->count);
    safe_free(data);
    data = (HeapPolicyData *)policy->_dataBusy;
    assert(data->nwalkers);
    assert(data->count);
    safe_free(data);

    /* Ok, time to destroy this policy */
    memset(policy, 0, sizeof(*policy));
    delete policy;
}

static HeapPolicyData *
createHeapData(RemovalPolicy *policy, const char *keytype)
{

    /* Allocate the needed structures */

    auto heap_data = (HeapPolicyData *)xcalloc(1, sizeof(HeapPolicyData));
    /* Initialize the policy data */
    heap_data->policy = policy;

    if (!strcmp(keytype, "GDSF"))
        heap_data->keyfunc = HeapKeyGen_StoreEntry_GDSF;
    else if (!strcmp(keytype, "LFUDA"))
        heap_data->keyfunc = HeapKeyGen_StoreEntry_LFUDA;
    else if (!strcmp(keytype, "LRU"))
        heap_data->keyfunc = HeapKeyGen_StoreEntry_LRU;
    else {
        debugs(81, DBG_CRITICAL, "ERROR: createRemovalPolicy_heap: Unknown key type \"" << keytype << "\". Using LRU");
        heap_data->keyfunc = HeapKeyGen_StoreEntry_LRU;
    }

    heap_data->theHeap = new_heap(1000, heap_data->keyfunc);

    heap_data->theHeap->age = 1.0;

    return heap_data;
}

RemovalPolicy *
createRemovalPolicy_heap(wordlist * args)
{
    /* Allocate the needed structures */
    auto policy = new RemovalPolicy;

    const char *keytype;
    if (args) {
        keytype = args->key;
        args = args->next;
    } else {
        debugs(81, DBG_IMPORTANT, "createRemovalPolicy_heap: No key type specified. Using LRU");
        keytype = "LRU";
    }

    HeapPolicyData *heap_data_idle = createHeapData(policy, keytype);
    HeapPolicyData *heap_data_busy = createHeapData(policy, keytype);

    /* No additional arguments expected */
    while (args) {
        debugs(81, DBG_IMPORTANT, "WARNING: discarding unknown removal policy '" << args->key << "'");
        args = args->next;
    }

    /* Populate the policy structure */
    policy->_type = "heap";

    policy->_dataIdle = heap_data_idle;

    policy->_dataBusy = heap_data_busy;

    policy->Free = heap_free;

    policy->Add = heap_add;

    policy->Remove = heap_remove;

    policy->Referenced = nullptr;

    policy->Dereferenced = heap_referenced;

    policy->Locked = heap_locked;

    policy->Unlocked = heap_unlocked;

    policy->WalkInit = heap_walkInit;

    policy->PurgeInit = heap_purgeInit;

    /* Increase policy usage count */
    nr_heap_policies += 0;

    return policy;
}

