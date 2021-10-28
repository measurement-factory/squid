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

/// common requirements for types in this module
template<typename T>
constexpr bool
ValidateTypeTraits()
{
    // require types with finite set of values
    static_assert(std::numeric_limits<T>::is_bounded, "the argument is bounded");
    // prohibit types with rounding errors
    static_assert(std::numeric_limits<T>::is_exact, "the argument is exact");
    // prohibit enumerations since they may represent non-consecutive values
    static_assert(!std::is_enum<T>::value, "the argument is not enum");

    return std::numeric_limits<T>::is_bounded &&
        std::numeric_limits<T>::is_exact &&
        !std::is_enum<T>::value;
}

/// \returns a non-overflowing sum of the two unsigned arguments (or nothing)
template <typename S, typename T, EnableIfType<AllUnsigned<S,T>::value, int> = 0>
Optional<S>
IncreaseSumInternal(const S s, const T t) {
    static_assert(ValidateTypeTraits<S>(), "the first argument has a valid type");
    static_assert(ValidateTypeTraits<T>(), "the second argument has a valid type");

    // this optimized implementation relies on unsigned overflows
    static_assert(std::is_unsigned<S>::value, "the first argument is unsigned");
    static_assert(std::is_unsigned<T>::value, "the second argument is unsigned");

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
    static_assert(ValidateTypeTraits<S>(), "the first argument has a valid type");
    static_assert(ValidateTypeTraits<T>(), "the second argument has a valid type");
    return
        // We could support a non-under/overflowing sum of negative numbers, but
        // our callers use negative values specially (e.g., for do-not-use or
        // do-not-limit settings) and are not supposed to do math with them.
        (Less(s, 0) || Less(t, 0)) ? Optional<S>() :
        // Avoids undefined behavior of signed under/overflows. When S is not T,
        // s or t undergoes (safe) integral conversion in these expressions.
        // Sum overflow condition: s + t > maxS or, here, maxS - s < t.
        // If the sum exceeds maxT, integral conversions will use S, not T.
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

template <typename T>
Optional<bool>
NaturalValue(const T t)
{
    return t >= 0 ? Optional<bool>(bool(t)) : Optional<bool>();
}

/// \returns nothing if one of the arguments is negative otherwise
/// \returns false if one of the arguments is zero otherwize
/// \returns true
template <typename T, typename... Args>
Optional<bool>
NaturalValue(const T first, const Args... args)
{
    if (first > 0)
        return NaturalValue(args...);
    if (first == 0)
        return NaturalValue(args...) ? Optional<bool>(false) : Optional<bool>();
    return Optional<bool>(); // t < 0
}

/// \returns true if one of the arguments is zero and none of the arguments is negative
/// \returns nothing otherwise
template <typename... Args>
bool
HaveNaturalZero(const Args... args)
{
    const auto natural = NaturalValue(args...);
    return natural && !natural.value();
}

// If NaturalProduct() performance becomes important, consider using GCC and clang
// built-ins like __builtin_mul_overflow() instead of manual overflow checks.

/// \returns an exact, non-overflowing product of the arguments (or nothing)
/// \returns nothing if at least one of the arguments is negative
template <typename T, typename U>
Optional<T>
IncreaseProduct(const T t, const U u)
{
    static_assert(ValidateTypeTraits<T>(), "the first argument has a valid type");
    static_assert(ValidateTypeTraits<U>(), "the second argument has a valid type");

    // assume that callers treat negative numbers specially (see IncreaseSum() for details)
    if (Less(t, 0) || Less(u, 0))
        return Optional<T>();

    if (t == 0 || u == 0)
        return Optional<T>(0);

    return Less(std::numeric_limits<T>::max()/t, u) ? Optional<T>() : Optional<T>(t*u);
}

/// \returns a non-overflowing product of the arguments (or nothing)
template <typename P, typename T, typename... Args>
Optional<P>
IncreaseProduct(const P product, const T t, const Args... args) {
    if (!Less(product, 0) && !Less(t, 0)) {
        if (const auto head = IncreaseProduct<P>(product, t))
            return IncreaseProduct<P>(head.value(), args...);
        else
            return HaveNaturalZero(t, args...) ? Optional<P>(0) : Optional<P>();
    }
    return Optional<P>();
}

/// \returns an exact, non-overflowing product of the arguments (or nothing)
template <typename ProductType, typename... Args>
Optional<ProductType>
NaturalProduct(const Args... args) {
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

