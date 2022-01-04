/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_OPTIONS_H
#define SQUID_ACL_OPTIONS_H

#include "acl/forward.h"
#include "sbuf/SBuf.h"

#include <iosfwd>
#include <vector>

// After line continuation is handled by the preprocessor, an ACL object
// configuration can be visualized as a sequence of same-name "acl ..." lines:
//
// L1: acl exampleA typeT parameter1 -i parameter2 parameter3
// L2: acl exampleA typeT parameter4
// L3: acl exampleA typeT -i -n parameter5 +i parameter6
// L4: acl exampleA typeT -n parameter7
//
// There are two kinds of ACL options (a.k.a. flags):
//
// * Global (e.g., `-n`): Applies to all parameters regardless of where the
//   option was discovered/parsed (e.g., `-n` on L3 affects parameter2 on L1).
//   Declared by ACL class kids (or equivalent) via ACL::options().
//
// * Line: (e.g., `-i`) Applies to the yet unparsed ACL parameters of the
//   current "acl ..." line (e.g., `-i` on L1 has no affect on parameter4 on L2)
//   Declared by ACLData class kids (or equivalent) via lineOptions().
//
// Here is the option:explicitly-affected-parameters map for the above exampleA:
//   `-n`: parameter1-7 (i.e. all parameters)
//   `-i`: parameter2, parameter3; parameter5
//   `+i`: parameter6
//
// The option name spelling determines the option kind and effect.
// Both option kinds use the same general option configuration syntax:
//   option = name[=value]
// where "name" is option-specific spelling that looks like -x, +x, or --long
//
// On each "acl ..." line, global options can only appear before the first
// parameter, while line options can go before any parameter.
//
// XXX: The fact that global options affect previous (and subsequent) same-name
// "acl name ..." lines surprises and confuses those who comprehend ACLs in
// terms of configuration lines (which Squid effectively merges together).

namespace Acl {

/// A single option supported by an ACL: -x[=value] or --name[=value]
class Option
{
public:
    typedef enum { valueNone, valueOptional, valueRequired } ValueExpectation;
    explicit Option(const char *onName, const char *offName = nullptr, ValueExpectation vex = valueNone):
        valueExpectation(vex), enableName(onName), disableName(offName) { assert(enableName); }
    virtual ~Option() {}

    /// clear configureDefault() and configureWith() effects
    virtual void unconfigure() const = 0;

    /// whether the admin explicitly specified this option
    /// (i.e., whether configureWith() or configureDefault() has been called)
    virtual bool configured() const = 0;

    /// called after parsing -x or --name
    virtual void configureDefault(const SBuf &optName) const = 0;

    /// called after parsing -x=value or --name=value
    virtual void configureWith(const SBuf &rawValue) const = 0;

    /// whether optName is one of the supported Option names
    virtual bool hasName(const SBuf &optName) const;

    virtual bool valued() const = 0;

    /// prints a configuration snippet (as an admin could have typed)
    virtual void print(std::ostream &os) const = 0;

    ValueExpectation valueExpectation = valueNone; ///< expect "=value" part?

protected:
    const char *enableName; ///< an option name, turning this Option on
    const char *disableName; ///< an option name, turning this Option off, may be nil
};

/// Stores configuration of a typical boolean flag or a single-value Option.
template <class Value>
class OptionValue
{
public:
    typedef Value value_type;

    OptionValue(): value {} {}
    explicit OptionValue(const Value &aValue): value(aValue) {}

    explicit operator bool() const = delete;

    /// go back to the default-initialized state
    void reset() { *this = OptionValue<Value>(); }

    Value value; ///< final value storage, possibly after conversions
    bool configured = false; ///< whether the option was present in squid.conf
    bool valued = false; ///< whether a configured option had a value
};

/// a type-specific Option (e.g., a boolean --toggle or -m=SBuf)
template <class Recipient>
class TypedOption: public Option
{
public:
    //typedef typename Recipient::value_type value_type;
    explicit TypedOption(const char *onName, const char *offName = nullptr, ValueExpectation vex = valueNone):
        Option(onName, offName, vex) {}

    /// who to tell when this option is enabled
    void linkWith(Recipient *recipient) const
    {
        assert(recipient);
        recipient_ = recipient;
    }

    /* Option API */

    virtual bool configured() const override { return recipient_ && recipient_->configured; }
    virtual bool valued() const override { return recipient_ && recipient_->valued; }

    virtual void unconfigure() const override {
        assert(recipient_);
        recipient_->reset();
    }

    virtual void configureDefault(const SBuf &optName) const override
    {
        assert(recipient_);
        recipient_->configured = true;
        recipient_->valued = false;
        setDefault(optName);
    }

    virtual void configureWith(const SBuf &rawValue) const override
    {
        assert(recipient_);
        recipient_->configured = true;
        recipient_->valued = true;
        import(rawValue);
    }

    virtual void print(std::ostream &os) const override
    {
        // TODO: print disableName (if needed) when it is supported for non-boolean options.
        os << enableName;
        if (valued())
            os << '=' << recipient_->value;
    }

private:
    void import(const SBuf &rawValue) const { recipient_->value = rawValue; }
    virtual void setDefault(const SBuf &) const { /*leave recipient_->value as is*/}

    // The "mutable" specifier demarcates set-once Option kind/behavior from the
    // ever-changing recipient of the actual admin-configured option value.
    mutable Recipient *recipient_ = nullptr; ///< parsing results storage
};

/* two typical option kinds: --foo and --bar=text  */
typedef OptionValue<bool> BooleanOptionValue;
typedef OptionValue<SBuf> TextOptionValue;
typedef TypedOption<BooleanOptionValue> BooleanOption;
typedef TypedOption<TextOptionValue> TextOption;

/// Convenience conversion to bool for boolean options. (False) boolean option
/// value is considered usable/correct even when the option is not configured.
template <>
inline
BooleanOptionValue::operator bool() const { return value; }

// this specialization should never be called until we start supporting
// boolean option values like --name=enable or --name=false
template <>
inline void
BooleanOption::import(const SBuf &) const
{
    assert(!"boolean options do not have ...=values (for now)");
}

template <>
inline void
BooleanOption::setDefault(const SBuf &optName) const
{
    // Set the boolean value depending on the specified flag name prefix
    // ('true' for '-' and 'false' otherwise, e.g., for '+').
    // In future, we may need adding support for other flag names,
    // such as --enable-foo and --disable-foo.
    recipient_->value = (optName[0] == '-');
}

template <>
inline void
BooleanOption::print(std::ostream &os) const
{
    Must(configured());
    if (recipient_->value) {
        os << enableName;
    } else {
        Must(disableName);
        os << disableName;
    }
}

typedef std::vector<const Option *> Options;

/// parses the flags part of the being-parsed ACL, filling Option values
/// \param options options supported by the ACL as a whole (e.g., -n)
void ParseFlags(const Options &options);

/* handy for Class::options() defaults */
const Options &NoOptions(); ///< \returns an empty Options container

/// A boolean option that controls case-sensitivity (-i/+i).
/// Defaults to "case sensitive" (+i).
const BooleanOption &CaseSensitivityOption();

} // namespace Acl

std::ostream &operator <<(std::ostream &os, const Acl::Option &option);
std::ostream &operator <<(std::ostream &os, const Acl::Options &options);

#endif /* SQUID_ACL_OPTIONS_H */

