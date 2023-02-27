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
    node->owner = nullptr;
}

static void
heap_add_to(StoreEntry *entry, RemovalPolicyNode *node, HeapPolicyData *policyData)
{
    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL))
        return;         /* We won't manage these.. they messes things up */

    if (node->owner == policyData) // already added
        return;

    assert(!node->inited());

    node->data = heap_insert(policyData->theHeap, entry);
    node->owner = policyData;

    policyData->count += 1;

    if (!policyData->type)
        policyData->type = heap_guessType(entry, node);

    /* Add a little more variance to the aging factor */
    policyData->theHeap->age += policyData->theHeap->age / 100000000;
}

static void
heap_add(RemovalPolicy *policy, StoreEntry *entry, RemovalPolicyNode *node)
{
    heap_add_to(entry, node, (HeapPolicyData *)policy->_dataIdle);
}

static void
heap_remove_from(RemovalPolicyNode *node, HeapPolicyData *policyData)
{
    if (!node->inited()) // already deleted
        return;

    heap_node *hnode = (heap_node *)node->data;
    if (!hnode)
        return;

    if (node->owner != policyData) // already moved to another heap
        return;

    heap_delete(policyData->theHeap, hnode);

    node->data = nullptr;
    node->owner = nullptr;

    policyData->count -= 1;
}

static void
heap_remove(RemovalPolicy * policy, StoreEntry *e,
            RemovalPolicyNode * node)
{
    assert(!e->locked());
    heap_remove_from(node, (HeapPolicyData *)policy->_dataIdle);
}

static void
heap_referenced(RemovalPolicy * policy, StoreEntry * entry,
                RemovalPolicyNode * node)
{
    auto hIdle = (HeapPolicyData *)policy->_dataIdle;
    auto hBusy = (HeapPolicyData *)policy->_dataBusy;
    if (!node->data)
        return;

    heap_remove_from(node, hIdle);
    heap_add_to(entry, node, hBusy);
}

static void
heap_dereferenced(RemovalPolicy * policy, StoreEntry * entry,
                RemovalPolicyNode * node)
{
    auto hIdle = (HeapPolicyData *)policy->_dataIdle;
    auto hBusy = (HeapPolicyData *)policy->_dataBusy;
    if (!node->data)
        return;

    heap_remove_from(node, hBusy);
    heap_add_to(entry, node, hIdle);
}

/** RemovalPolicyWalker **/

typedef struct _HeapWalkData HeapWalkData;

struct _HeapWalkData {
    size_t current;
};

static const StoreEntry *
heap_walkNext(RemovalPolicyWalker * walker)
{
    auto heap_walk_idle = (HeapWalkData *)walker->_dataIdle;
    auto heap_walk_busy = (HeapWalkData *)walker->_dataBusy;
    RemovalPolicy *policy = walker->_policy;
    HeapPolicyData *dataIdle = (HeapPolicyData *)policy->_dataIdle;
    HeapPolicyData *dataBusy = (HeapPolicyData *)policy->_dataBusy;

    if (heap_walk_idle->current < heap_nodes(dataIdle->theHeap))
        return (StoreEntry *)heap_peep(dataIdle->theHeap, heap_walk_idle->current++);
    if (heap_walk_busy->current < heap_nodes(dataBusy->theHeap))
        return (StoreEntry *)heap_peep(dataBusy->theHeap, heap_walk_busy->current++);
    return nullptr;
}

static void
heap_walkDone(RemovalPolicyWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    auto hIdle = (HeapPolicyData *)policy->_dataIdle;
    auto hBusy = (HeapPolicyData *)policy->_dataBusy;
    assert(strcmp(policy->_type, "heap") == 0);
    assert(hIdle->nwalkers > 0);
    assert(hIdle->nwalkers > 0);
    hIdle->nwalkers -= 1;
    hBusy->nwalkers -= 1;
    safe_free(walker->_dataIdle);
    safe_free(walker->_dataBusy);
    delete walker;
}

static RemovalPolicyWalker *
heap_walkInit(RemovalPolicy * policy)
{
    auto hIdle = (HeapPolicyData *)policy->_dataIdle;
    auto hBusy = (HeapPolicyData *)policy->_dataBusy;
    RemovalPolicyWalker *walker;
    HeapWalkData *heap_walk_idle;
    HeapWalkData *heap_walk_busy;
    hIdle->nwalkers += 1;
    hBusy->nwalkers += 1;
    walker = new RemovalPolicyWalker;
    heap_walk_idle = (HeapWalkData *)xcalloc(1, sizeof(*heap_walk_idle));
    heap_walk_idle->current = 0;
    heap_walk_busy = (HeapWalkData *)xcalloc(1, sizeof(*heap_walk_busy));
    heap_walk_busy->current = 0;
    walker->_policy = policy;
    walker->_dataIdle = heap_walk_idle;
    walker->_dataBusy = heap_walk_busy;
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
    auto heap_walker = (HeapPurgeData *)walker->_dataIdle;
    RemovalPolicy *policy = walker->_policy;
    auto h = (HeapPolicyData *)policy->_dataIdle;
    StoreEntry *entry;
    heap_key age;

    if (heap_empty(h->theHeap))
        return nullptr;        /* done */

    age = heap_peepminkey(h->theHeap);

    entry = (StoreEntry *)heap_extractmin(h->theHeap);

    heap_walker->min_age = age;
    h->resetPolicyNode(entry);
    return entry;
}

static void
heap_purgeDone(RemovalPurgeWalker * walker)
{
    auto heap_walker = (HeapPurgeData *)walker->_dataIdle;
    RemovalPolicy *policy = walker->_policy;
    auto h = (HeapPolicyData *)policy->_dataIdle;
    assert(strcmp(policy->_type, "heap") == 0);
    assert(h->nwalkers > 0);
    h->nwalkers -= 1;

    if (heap_walker->min_age > 0) {
        h->theHeap->age = heap_walker->min_age;
        debugs(81, 3, "Heap age set to " << h->theHeap->age);
    }

    delete heap_walker;
    delete walker;
}

static RemovalPurgeWalker *
heap_purgeInit(RemovalPolicy * policy, int max_scan)
{
    auto h = (HeapPolicyData *)policy->_dataIdle;
    RemovalPurgeWalker *walker;
    HeapPurgeData *heap_walk;
    h->nwalkers += 1;
    walker = new RemovalPurgeWalker;
    heap_walk = new HeapPurgeData;
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
    auto h = (HeapPolicyData *)policy->_dataIdle;
    /* Make some verification of the policy state */
    assert(strcmp(policy->_type, "heap") == 0);
    assert(h->nwalkers);
    assert(h->count);
    safe_free(h);
    h = (HeapPolicyData *)policy->_dataBusy;
    assert(h->nwalkers);
    assert(h->count);
    safe_free(h);

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

    policy->Referenced = heap_referenced;

    policy->Dereferenced = heap_dereferenced;

    policy->WalkInit = heap_walkInit;

    policy->PurgeInit = heap_purgeInit;

    /* Increase policy usage count */
    nr_heap_policies += 0;

    return policy;
}

