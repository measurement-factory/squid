/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STMEM_H
#define SQUID_STMEM_H

#include "base/Range.h"
#include "splay.h"

class mem_node;

class StoreIOBuffer;

class mem_hdr
{

public:
    mem_hdr();
    ~mem_hdr();
    void freeContent();
    int64_t lowestOffset () const;
    int64_t endOffset () const;
    int64_t freeDataUpto (int64_t);
    ssize_t copy (StoreIOBuffer const &) const;
    bool hasContigousContentRange(Range<int64_t> const &range) const;
    /* success or fail */
    void write(StoreIOBuffer const &, bool locked);
    void dump() const;
    size_t size() const;
    /* Not an iterator - thus the start, not begin() */
    mem_node const *start() const;
    mem_node *getBlockContainingLocation (int64_t location) const;
    /// called when the possessing entry becomes busy/locked
    void markBusy();
    /// called when the possessing entry becomes idle
    void markIdle();
    /* access the contained nodes - easier than punning
     * as a container ourselves
     */
    const Splay<mem_node *> &getNodes() const;
    char * NodeGet(mem_node * aNode);

    static Splay<mem_node *>::SPLAYCMP NodeCompare;

private:
    void debugDump() const;
    bool unlink(mem_node *aNode);
    int appendToNode(mem_node *aNode, const char *data, int maxLength);
    void appendNode (mem_node *aNode);
    size_t copyAvailable(mem_node *aNode, int64_t location, size_t amount, char *target) const;
    bool unionNotEmpty (StoreIOBuffer const &);
    mem_node *nodeToRecieve(int64_t offset);
    size_t writeAvailable(mem_node *aNode, int64_t location, size_t amount, char const *source);
    int64_t freeDataUptoImpl(int64_t);
    bool writeImpl(const StoreIOBuffer &);
    void updateIdleNodesNumber(const size_t oldSize);
    int64_t inmem_hi;
    Splay<mem_node *> nodes;
    bool isIdle; ///< whether the associated pages belong to an unlocked StoreEntry
};

#endif /* SQUID_STMEM_H */

