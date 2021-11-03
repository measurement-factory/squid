/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_SQUIDMATH_H
#define _SQUID_SRC_SQUIDMATH_H

#include "base/forward.h"
#include "base/Optional.h"

#include <limits>
#include <type_traits>

// TODO: Move to src/base/Math.h and drop the Math namespace

/* Math functions we define locally for Squid */
namespace Math
{

int intPercent(const int a, const int b);
int64_t int64Percent(const int64_t a, const int64_t b);
double doublePercent(const double, const double);
int intAverage(const int, const int, int, const int);
double doubleAverage(const double, const double, int, const int);

} // namespace Math

// If Sum() performance becomes important, consider using GCC and clang
// built-ins like __builtin_add_overflow() instead of manual overflow checks.

/// std::enable_if_t replacement until C++14
/// simplifies Sum() declarations below
template <bool B, class T = void>
using EnableIfType = typename std::enable_if<B,T>::type;

/// detects a pair of unsigned types
/// reduces code duplication in Sum() declarations below
template <typename A, typename B>
using AllUnsigned = typename std::conditional<
                    std::is_unsigned<A>::value && std::is_unsigned<B>::value,
                    std::true_type,
                    std::false_type
                    >::type;

// TODO: Replace with std::cmp_less() after migrating to C++20.
/// whether integer a is less than integer b, with correct overflow handling
template <typename A, typename B>
constexpr bool
Less(const A a, const B b) {
    // The casts below make standard C++ integral conversions explicit. They
    // quell compiler warnings about signed/unsigned comparison. The first two
    // lines exclude different-sign a and b, making the casts/comparison safe.
    using AB = typename std::common_type<A, B>::type;
    return
        (a >= 0 && b < 0) ? false :
        (a < 0 && b >= 0) ? true :
        /* (a >= 0) == (b >= 0) */ static_cast<AB>(a) < static_cast<AB>(b);
}

/// ensure that T is supported by NaturalSum() and friends
template<typename T>
constexpr void
AssertNaturalType()
{
    static_assert(std::numeric_limits<T>::is_bounded, "std::numeric_limits<T>::max() is meaningful");
    static_assert(std::numeric_limits<T>::is_exact, "no silent loss of precision");
    static_assert(!std::is_enum<T>::value, "no silent creation of non-enumerated values");
}

/// \returns a non-overflowing sum of the two unsigned arguments (or nothing)
template <typename S, typename T, EnableIfType<AllUnsigned<S,T>::value, int> = 0>
Optional<S>
IncreaseSumInternal(const S s, const T t) {
    AssertNaturalType<S>();
    AssertNaturalType<T>();

    // For the sum overflow check below to work, we cannot restrict the sum
    // type which, due to integral promotions, may exceed common_type<S,T>!
    const auto sum = s + t;
    static_assert(std::numeric_limits<decltype(sum)>::is_modulo, "we can detect overflows");
    // 1. modulo math: overflowed sum is smaller than any of its operands
    // 2. the unknown (see above) "auto" type may hold more than S can hold
    return (s <= sum && sum <= std::numeric_limits<S>::max()) ?
           Optional<S>(sum) : Optional<S>();
}

/// \returns a non-overflowing sum of the two arguments (or nothing)
/// \returns nothing if at least one of the arguments is negative
/// at least one of the arguments is signed
template <typename S, typename T, EnableIfType<!AllUnsigned<S,T>::value, int> = 0>
Optional<S> constexpr
IncreaseSumInternal(const S s, const T t) {
    AssertNaturalType<S>();
    AssertNaturalType<T>();
    return
        // We could support a non-under/overflowing sum of negative numbers, but
        // our callers use negative values specially (e.g., for do-not-use or
        // do-not-limit settings) and are not supposed to do math with them.
        (s < 0 || t < 0) ? Optional<S>() :
        // To avoid undefined behavior of signed overflow, we must not compute
        // the raw s+t sum if it may overflow. When S is not T, s or t undergoes
        // (safe for non-negatives) integral conversion in these expressions, so
        // we do not know the resulting s+t type ST and its maximum. We must
        // also detect subsequent casting-to-S overflows.
        // Overflow condition: (s + t > maxST) or (s + t > maxS).
        // Since maxS <= maxST, it is sufficient to just check: s + t > maxS,
        // which is the same as the overflow-safe condition here: maxS - s < t.
        Less(std::numeric_limits<S>::max() - s, t) ? Optional<S>() :
        Optional<S>(s + t);
}

template <typename S, typename T>
Optional<S>
IncreaseSum(const S s, const T t)
{
    return IncreaseSumInternal<S>(+s, +t);
}

/// \returns a non-overflowing sum of the arguments (or nothing)
template <typename S, typename T, typename... Args>
Optional<S>
IncreaseSum(const S sum, const T t, const Args... args) {
    if (const auto head = IncreaseSumInternal<S>(+sum, +t)) {
        return IncreaseSum<S>(head.value(), args...);
    } else {
        return Optional<S>();
    }
}

/// \returns an exact, non-overflowing sum of the arguments (or nothing)
template <typename SummationType, typename... Args>
Optional<SummationType>
NaturalSum(const Args... args) {
    return IncreaseSum<SummationType>(0, args...);
}

/// Safely resets the given variable to NaturalSum() of the given arguments.
/// If the sum overflows, resets to variable's maximum possible value.
/// \returns the new variable value (like an assignment operator would)
template <typename S, typename... Args>
S
SetToNaturalSumOrMax(S &var, const Args... args)
{
    var = NaturalSum<S>(args...).value_or(std::numeric_limits<S>::max());
    return var;
}

// If NaturalProduct() performance becomes important, consider using GCC and clang
// built-ins like __builtin_mul_overflow() instead of manual overflow checks.

template <typename ProductType, typename... Args>
Optional<ProductType>
NaturalProduct(const Args... args);

/// argument pack expansion termination for IncreaseProduct<P, T, Args...>()
template <typename P, typename T>
Optional<P>
IncreaseProduct(const P p, const T t)
{
    AssertNaturalType<P>();
    AssertNaturalType<T>();

    // assume that callers treat negative numbers specially (see IncreaseSum() for details)
    if (p < 0 || t < 0)
        return Optional<P>();

    if (p == 0 || t == 0)
        return Optional<P>(0);

    // Overflow condition: (p * t > maxTU) or (p * t > maxT).
    // Since maxT <= maxTU, it is sufficient to just check: p * t > maxT.
    // We use its overflow-safe equivalent (for positive p): maxT/p < t.
    // For details, see IncreaseSumInternal() for signed arguments.
    return Less(std::numeric_limits<P>::max()/p, t) ?
        Optional<P>() : Optional<P>(p*t);
}

/// \returns an exact, non-overflowing product of the arguments (or nothing)
/// using the first argument type for the underlying integer return type
template <typename P, typename T, typename... Args>
Optional<P>
IncreaseProduct(const P p, const T t, const Args... args) {
    if (const auto head = IncreaseProduct<P>(p, t))
        return IncreaseProduct(head.value(), args...); // common case

    // we are dealing with either negative argument(s) or overflow

    if (p < 0 || t < 0)
        return Optional<P>();

    // check whether p*t overflow above is cured by a subsequent zero

    if (const auto tail = NaturalProduct<P>(args...))
        if (tail.value() == 0)
            return tail; // Optional<P>(0)

    return Optional<P>(); // p*t overflow without subsequent zeros
}

/// \returns an exact, non-overflowing product of the arguments (or nothing)
/// using ProductType for the underlying integer return type
template <typename ProductType, typename... Args>
Optional<ProductType>
NaturalProduct(const Args... args) {
    static_assert(!Less(std::numeric_limits<ProductType>::max(), 1), "casting 1 to ProductType is safe");
    return IncreaseProduct<ProductType>(1, args...);
}

/// Safely resets the given variable to NatrualProduct() of the given arguments.
/// If the product overflows, resets to variable's maximum possible value.
/// \returns the new variable value (like an assignment operator would)
template <typename P, typename... Args>
P
SetToNaturalProductOrMax(P &var, const Args... args)
{
    var = NaturalProduct<P>(args...).value_or(std::numeric_limits<P>::max());
    return var;
}

template<class T>
T MaxValue(T&)
{
    return std::numeric_limits<T>::max();
}

#endif /* _SQUID_SRC_SQUIDMATH_H */

