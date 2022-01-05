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
#include "sbuf/forward.h"

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
// * Global (e.g., "-n"): Applies to all parameters regardless of where the
//   option was discovered/parsed (e.g., "-n" on L3 affects parameter2 on L1).
//   Declared by ACL class kids (or equivalent) via ACL::options().
//
// * Line: (e.g., "-i") Applies to the yet unparsed ACL parameters of the
//   current "acl ..." line (e.g., "-i" on L1 has no affect on parameter4 on L2)
//   Declared by ACLData class kids (or equivalent) via lineOptions().
//
// Here is the option:explicitly-affected-parameters map for the above exampleA:
//   "-n": parameter1-7 (i.e. all parameters)
//   "-i": parameter2, parameter3; parameter5
//   "+i": parameter6
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

    /// whether the admin explicitly specified this option (i.e., whether
    /// enable(), configureWith(), or disable() has been called)
    virtual bool configured() const = 0;

    /// called after parsing enableName without a value (e.g., -x or --enable-x)
    virtual void enable() const = 0;

    /// called after parsing enableName and a value (e.g., -x=v or --enable-x=v)
    virtual void configureWith(const SBuf &rawValue) const = 0;

    /// called after parsing disableName (e.g., +i or --disable-x)
    virtual void disable() const = 0;

    /// clear enable(), configureWith(), or disable() effects
    virtual void unconfigure() const = 0;

    /// whether disable() has been called
    virtual bool disabled() const = 0;

    virtual bool valued() const = 0;

    /// prints a configuration snippet (as an admin could have typed)
    virtual void print(std::ostream &os) const = 0;

    ValueExpectation valueExpectation = valueNone; ///< expect "=value" part?

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

    /// whether the option is enabled (with or without a value)
    bool enabled() const { return configured && !disabled; }
    explicit operator bool() const { return enabled(); }

    /// go back to the default-initialized state
    void reset() { *this = OptionValue<Value>(); }

    Value value; ///< final value storage, possibly after conversions
    bool configured = false; ///< whether the option was present in squid.conf
    bool valued = false; ///< whether a configured option had a value
    bool disabled = false; ///< whether the option was explicitly turned off
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
    virtual bool disabled() const override { return recipient_ && recipient_->disabled && /* paranoid: */ disableName; }

    virtual void unconfigure() const override {
        assert(recipient_);
        recipient_->reset();
    }

    virtual void enable() const override
    {
        assert(recipient_);
        recipient_->configured = true;
        recipient_->valued = false;
        // leave recipient_->value unchanged
    }

    virtual void configureWith(const SBuf &rawValue) const override
    {
        assert(recipient_);
        recipient_->configured = true;
        recipient_->valued = true;
        import(rawValue);
    }

    virtual void disable() const override
    {
        assert(recipient_);
        recipient_->configured = true;
        recipient_->valued = false;
        // leave recipient_->value unchanged
    }

    virtual void print(std::ostream &os) const override
    {
        if (configured()) {
            os << (disabled() ? disableName : enableName);
            if (valued())
                os << '=' << recipient_->value;
        }
        // else do not report the implicit default
    }

private:
    void import(const SBuf &rawValue) const { recipient_->value = rawValue; }

    // The "mutable" specifier demarcates set-once Option kind/behavior from the
    // ever-changing recipient of the actual admin-configured option value.
    mutable Recipient *recipient_ = nullptr; ///< parsing results storage
};

/* two typical option kinds: --foo and --bar=text  */
typedef OptionValue<bool> BooleanOptionValue;
typedef OptionValue<SBuf> TextOptionValue;
typedef TypedOption<BooleanOptionValue> BooleanOption;
typedef TypedOption<TextOptionValue> TextOption;

// this specialization should never be called until we start supporting
// boolean option values like --name=enable or --name=false
template <>
inline void
BooleanOption::import(const SBuf &) const
{
    assert(!"boolean options do not have ...=values (for now)");
}

using Options = std::vector<const Option *>;

/// parses the flags part of the being-parsed ACL, filling Option values
/// \param options options supported by the ACL as a whole (e.g., -n)
void ParseFlags(const Options &options);

/* handy for Class::options() and lineOptions() defaults */
const Options &NoOptions(); ///< \returns an empty Options container

/// A boolean option that controls case-sensitivity (-i/+i).
/// An enabled (-i) state is "case insensitive".
/// A disabled (+i) and default states are "case sensitive".
const BooleanOption &CaseSensitivityOption();

} // namespace Acl

std::ostream &operator <<(std::ostream &os, const Acl::Option &option);
std::ostream &operator <<(std::ostream &os, const Acl::Options &options);

#endif /* SQUID_ACL_OPTIONS_H */

