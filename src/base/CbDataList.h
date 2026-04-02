/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_CBDATALIST_H
#define SQUID_SRC_BASE_CBDATALIST_H

#include "cbdata.h"

template <class C>
class CbDataList
{
    CBDATA_CLASS(CbDataList);

public:
    CbDataList(C const &);
    ~CbDataList();

    /// If element is already in the list, returns false.
    /// Otherwise, adds the element to the end of the list and returns true.
    /// Exists to avoid double iteration of find() and push() combo.
    bool push_back_unique(C const &element);
    bool find(C const &)const;
    CbDataList *next;
    C element;
};

template<class C>
class CbDataListContainer
{

public:
    CbDataListContainer();
    ~CbDataListContainer();
    CbDataList<C> *push_back (C const &);
    bool empty() const;

    CbDataList<C> *head;
};

template<class C>
class CbDataListIterator
{
public:
    CbDataListIterator(CbDataListContainer<C> const &list) : next_entry(list.head) {}
    const C & next() {
        CbDataList<C> *entry = next_entry;
        if (entry)
            next_entry = entry->next;
        return entry->element;
    }
    bool end() {
        return next_entry == nullptr;
    }

private:
    CbDataList<C> *next_entry;
};

/** \cond AUTODOCS_IGNORE */
template <class C>
cbdata_type CbDataList<C>::CBDATA_CbDataList = CBDATA_UNKNOWN;
/** \endcond */

template <class C>
CbDataList<C>::CbDataList(C const &value) : next(nullptr), element (value)
{}

template <class C>
CbDataList<C>::~CbDataList()
{
    if (next)
        delete next;
}

template <class C>
bool
CbDataList<C>::push_back_unique(C const &toAdd)
{
    CbDataList<C> *last;
    for (last = this; last->next; last = last->next) {
        if (last->element == toAdd)
            return false;
    }

    last->next = new CbDataList<C>(toAdd);
    return true;
}

template <class C>
bool
CbDataList<C>::find (C const &toFind) const
{
    CbDataList<C> const *node = nullptr;

    for (node = this; node; node = node->next)
        if (node->element == toFind)
            return true;

    return false;
}

template <class C>
CbDataListContainer<C>::CbDataListContainer() : head (nullptr)
{}

template <class C>
CbDataListContainer<C>::~CbDataListContainer()
{
    if (head)
        delete head;
}

template <class C>
CbDataList<C> *
CbDataListContainer<C>::push_back (C const &element)
{
    CbDataList<C> *node = new CbDataList<C> (element);

    if (head) {
        CbDataList<C> *tempNode = nullptr;

        for (tempNode = head; tempNode->next; tempNode = tempNode->next);
        tempNode->next = node;
    } else
        head = node;

    return node;
}

template <class C>
bool
CbDataListContainer<C>::empty() const
{
    return head == nullptr;
}

#endif /* SQUID_SRC_BASE_CBDATALIST_H */

