/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_GENERIC_H
#define SQUID_SRC_GENERIC_H

#include "dlink.h"

#include <ostream>

template <class _Arg, class _Result>
struct unary_function {
    typedef _Arg argument_type;
    typedef _Result result_type;
};

template <class T>
T& for_each(dlink_list const &collection, T& visitor)
{
    for (dlink_node const *node = collection.head; node; node=node->next)
        visitor(*(typename T::argument_type const *)node->data);

    return visitor;
}

/* RBC 20030718 - use this to provide instance expecting classes a pointer to a
 * singleton
 */

template <class C>
class InstanceToSingletonAdapter : public C
{

public:

private:
    C const *theInstance;
};

/* generic ostream printer */
template <class Pointer>
struct PointerPrinter {
    PointerPrinter(std::ostream &astream, std::string aDelimiter) : os(astream), delimiter (aDelimiter) {}

    void operator () (Pointer aNode) {
        os << *aNode << delimiter;
    }

    std::ostream &os;
    std::string delimiter;
};

#endif /* SQUID_SRC_GENERIC_H */

