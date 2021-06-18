/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUFALGOS_H_
#define SQUID_SBUFALGOS_H_

#include "sbuf/SBuf.h"

#include <algorithm>
#include <numeric>
#include <utility>

/// SBuf equality predicate for STL algorithms etc
class SBufEqual
{
public:
    explicit SBufEqual(const SBuf &reference, SBufCaseSensitive sensitivity = caseSensitive) :
        reference_(reference), sensitivity_(sensitivity) {}
    bool operator() (const SBuf & checking) { return checking.compare(reference_,sensitivity_) == 0; }
private:
    SBuf reference_;
    SBufCaseSensitive sensitivity_;
};

/// SBuf "starts with" predicate for STL algorithms etc
class SBufStartsWith
{
public:
    explicit SBufStartsWith(const SBuf &prefix, SBufCaseSensitive sensitivity = caseSensitive) :
        prefix_(prefix), sensitivity_(sensitivity) {}
    bool operator() (const SBuf & checking) { return checking.startsWith(prefix_,sensitivity_); }
private:
    SBuf prefix_;
    SBufCaseSensitive sensitivity_;
};

/** SBuf size addition accumulator for STL contaniners
 *
 * Equivalent to prefix_length +  SBuf.length() +  separator.length()
 */
class SBufAddLength
{
public:
    explicit SBufAddLength(const SBuf &separator) :
        separatorLen_(separator.length()) {}
    SBuf::size_type operator()(const SBuf::size_type sz, const SBuf & item) {
        return sz + item.length() + separatorLen_;
    }
private:
    SBuf::size_type separatorLen_;
};

/** Join container of SBufs and append to supplied target
 *
 * append to the target SBuf all elements in the [begin,end) range from
 * an iterable container, prefixed by prefix, separated by separator and
 * followed by suffix. Prefix and suffix are added also in case of empty
 * iterable
 *
 * \return the modified dest
 */
template <class ContainerIterator>
SBuf&
JoinContainerIntoSBuf(SBuf &dest, const ContainerIterator &begin,
                      const ContainerIterator &end, const SBuf& separator,
                      const SBuf& prefix = SBuf(), const SBuf& suffix = SBuf())
{
    if (begin == end) {
        dest.append(prefix).append(suffix);
        return dest;
    }

    // optimization: pre-calculate needed storage
    const SBuf::size_type totalContainerSize =
        std::accumulate(begin, end, 0, SBufAddLength(separator)) +
        dest.length() + prefix.length() + suffix.length();
    SBufReservationRequirements req;
    req.minSpace = totalContainerSize;
    dest.reserve(req);

    auto i = begin;
    dest.append(prefix);
    dest.append(*i);
    ++i;
    for (; i != end; ++i)
        dest.append(separator).append(*i);
    dest.append(suffix);
    return dest;
}

/// convenience wrapper of JoinContainerIntoSBuf with no caller-supplied SBuf
template <class ContainerIterator>
SBuf
JoinContainerToSBuf(const ContainerIterator &begin,
                    const ContainerIterator &end, const SBuf& separator,
                    const SBuf& prefix = SBuf(), const SBuf& suffix = SBuf())
{
    SBuf rv;
    return JoinContainerIntoSBuf(rv, begin, end, separator, prefix, suffix);
}

namespace std {
/// default hash functor to support std::unordered_map<SBuf,*>
template <>
struct hash<SBuf>
{
    size_t operator()(const SBuf &) const noexcept;
};
}

/// case-insensitive hashing functor for SBufs; \see CaseInsensitiveSBufMap
class CaseInsensitiveSBufHash
{
public:
    std::size_t operator()(const SBuf &) const noexcept;
};

/// case-insensitive equality functor for SBufs; \see CaseInsensitiveSBufMap
class CaseInsensitiveSBufEqual
{
public:
    std::size_t operator()(const SBuf &a, const SBuf &b) const noexcept
    {
        return a.caseCmp(b) == 0;
    }
};

/// Safety wrapper for declaring a case-insensitive pooled hash with SBuf keys.
/// Simplifies declaration and avoids inconsistent hashing/equality functors.
/// The Map parameter is expected to follow std::unordered_map API, but that
/// obvious choice is not hard-coded to avoid spamming other header users.
template <
    template<typename,typename,typename,typename,typename> class Map,
    typename Value,
    template<typename> class Allocator>
using CaseInsensitiveSBufMap = Map<SBuf, Value,
    CaseInsensitiveSBufHash,
    CaseInsensitiveSBufEqual,
    Allocator< std::pair<const SBuf, Value> >
>;

#endif /* SQUID_SBUFALGOS_H_ */

