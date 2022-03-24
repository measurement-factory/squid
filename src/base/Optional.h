/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_BASE_OPTIONAL_H
#define SQUID__SRC_BASE_OPTIONAL_H

#include <exception>
#include <type_traits>
#include <utility>

/// std::bad_optional_access replacement (until we upgrade to C++17)
class BadOptionalAccess: public std::exception
{
public:
    BadOptionalAccess() {}
    /* std::exception API */
    virtual const char* what() const noexcept override { return "bad-optional-access"; }
    virtual ~BadOptionalAccess() noexcept = default;
};

template <class T>
union OptionalStorage
{
    OptionalStorage() : dummy_(0) {};
    OptionalStorage(const T& v) : value_(v) {};

    ~OptionalStorage(){ value_.~T(); }

    unsigned char dummy_;
    T value_;
};

/// (limited) std::optional replacement (until we upgrade to C++17)
template <typename Value>
class Optional
{
public:
    // std::optional supports non-trivial types as well, but we
    // do not want to fiddle with unions to disable default Value constructor
    // until that work becomes necessary
//    static_assert(std::is_trivial<Value>::value, "Value is trivial");

    constexpr Optional() noexcept {}
    constexpr explicit Optional(const Value &v): storage_(v), hasValue_(true) {}

    constexpr explicit operator bool() const noexcept { return hasValue_; }
    constexpr bool has_value() const noexcept { return hasValue_; }

    const Value &value() const &
    {
        if (!hasValue_)
            throw BadOptionalAccess();
        return storage_.value_;
    }

    template <class Other>
    constexpr Value value_or(Other &&defaultValue) const &
    {
        return hasValue_ ? storage_.value_ : static_cast<Value>(std::forward<Other>(defaultValue));
    }

    template <class Other = Value>
    Optional &operator =(Other &&otherValue)
    {
        storage_.value_ = std::forward<Other>(otherValue);
        hasValue_ = true;
        return *this;
    }

private:
    OptionalStorage<Value> storage_; // stored value; inaccessible/uninitialized unless hasValue_
    bool hasValue_ = false;
};

#endif /* SQUID__SRC_BASE_OPTIONAL_H */

