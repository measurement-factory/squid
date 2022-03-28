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

/// (limited) std::optional replacement (until we upgrade to C++17)
template <typename Value>
class Optional
{
public:
    constexpr Optional() noexcept : dummy_(0) {}
    constexpr explicit Optional(const Value &v): value_(v), hasValue_(true) {}
    ~Optional() { clear(); }

    Optional(const Optional &other) = delete;
    Optional &operator=(const Optional &other) = delete;
    constexpr Optional(Optional &&other) = default;

    template <class Other = Value>
    Optional &operator=(Optional<Other> &&other) {
        if (this != &other) {
            if (!other.has_value()) {
                clear();
            } else {
                *this = other.value();
                other.clear();
            }
        }
        return *this;
    }

    constexpr explicit operator bool() const noexcept { return hasValue_; }
    constexpr bool has_value() const noexcept { return hasValue_; }

    const Value &value() const &
    {
        if (!hasValue_)
            throw BadOptionalAccess();
        return value_;
    }

    template <class Other>
    constexpr Value value_or(Other &&defaultValue) const &
    {
        return hasValue_ ? value_ : static_cast<Value>(std::forward<Other>(defaultValue));
    }

    template <class Other = Value>
    Optional &operator =(Other &&otherValue)
    {
        value_ = std::forward<Other>(otherValue);
        hasValue_ = true;
        return *this;
    }

    void clear() {
        if (hasValue_) {
            value_.~Value();
            hasValue_ = false;
        }
    }

private:
    union {
        unsigned char dummy_;
        // stored value; inaccessible/uninitialized unless hasValue_
        Value value_;
    };

    bool hasValue_ = false;
};

#endif /* SQUID__SRC_BASE_OPTIONAL_H */

