/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_IO_MANIP_H
#define SQUID_SRC_BASE_IO_MANIP_H

#include <iostream>
#include <iomanip>

/// debugs objects pointed by possibly nil pointers: label=object
template <class Pointer>
class RawPointerT {
public:
    RawPointerT(const char *aLabel, const Pointer &aPtr):
        label(aLabel), ptr(aPtr) {}
    const char *label; /// the name or description of the being-debugged object
    const Pointer &ptr; /// a possibly nil pointer to the being-debugged object
};

/// convenience wrapper for creating  RawPointerT<> objects
template <class Pointer>
inline RawPointerT<Pointer>
RawPointer(const char *label, const Pointer &ptr)
{
    return RawPointerT<Pointer>(label, ptr);
}

/// prints RawPointerT<>, dereferencing the io_manip pointer if possible
template <class Pointer>
inline std::ostream &
operator <<(std::ostream &os, const RawPointerT<Pointer> &pd)
{
    os << pd.label << '=';
    if (pd.ptr)
        os << *pd.ptr;
    else
        os << "[nil]";
    return os;
}

/// std::ostream manipulator to print integers as hex numbers prefixed by 0x
template <class Integer>
class AsHex
{
public:
    explicit AsHex(const Integer n): io_manip(n) {}
    Integer io_manip; ///< the integer to print
};

template <class Integer>
inline std::ostream &
operator <<(std::ostream &os, const AsHex<Integer> number)
{
    const auto oldFlags = os.flags();
    os << std::hex << std::showbase << number.io_manip;
    os.setf(oldFlags);
    return os;
}

/// a helper to ease AsHex object creation
template <class Integer>
inline AsHex<Integer> asHex(const Integer n) { return AsHex<Integer>(n); }

/// Prints the first n data bytes using hex notation. Does nothing if n is 0.
void PrintHex(std::ostream &, const char *data, size_t n);

#endif /* SQUID_SRC_BASE_IO_MANIP_H */

