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

// After all same-name acl configuration lines are merged into one ACL:
//   configuration = acl name type [option...] [[flag...] parameter...]
//   option = -x[=value] | --name[=value]
//   flag = option
//
// Options and flags use the same syntax, but differ in scope and handling code:
// * ACL options appear before all parameters and apply to all parameters.
//   They are handled by ACL kids (or equivalent).
// * Parameter flags may appear after some other parameters and apply only to
//   the subsequent parameters (until they are overwritten by later flags).
//   They are handled by ACLData kids.
// ACL options parsing code skips and leaves leading parameter flags (if any)
// for ACLData code to process.

namespace Acl {

/// A single option supported by an ACL: -x[=value] or --name[=value]
/// Unlike a parameter flag, this option applies to all ACL parameters.
class Option
{
public:
    typedef enum { valueNone, valueOptional, valueRequired } ValueExpectation;
    explicit Option(ValueExpectation vex = valueNone): valueExpectation(vex) {}
    virtual ~Option() {}

    /// whether the admin explicitly specified this option
    /// (i.e., whether configureWith() or configureFlag() has been called)
    virtual bool configured() const = 0;

    /// called after parsing -x, +x, or --name
    virtual void configureFlag(bool flagValue) const = 0;

    /// called after parsing -x=value or --name=value
    virtual void configureWith(const SBuf &rawValue) const = 0;

    virtual bool valued() const = 0;

    /// prints a configuration snippet (as an admin could have typed)
    virtual void print(std::ostream &os) const = 0;

    ValueExpectation valueExpectation = valueNone; ///< expect "=value" part?
};

/// Stores configuration of a typical boolean flag or a single-value Option.
template <class Value>
class OptionValue
{
public:
    typedef Value value_type;

    OptionValue(): value {} {}
    explicit OptionValue(const Value &aValue): value(aValue) {}

    explicit operator bool() const { return configured; }

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
    explicit TypedOption(ValueExpectation vex = valueNone): Option(vex) {}

    /// who to tell when this option is enabled
    void linkWith(Recipient *recipient) const
    {
        assert(recipient);
        recipient_ = recipient;
    }

    /* Option API */

    virtual bool configured() const override { return recipient_ && recipient_->configured; }
    virtual bool valued() const override { return recipient_ && recipient_->valued; }

    /// sets the flag value
    virtual void configureFlag(bool flagValue) const override
    {
        assert(recipient_);
        recipient_->configured = true;
        recipient_->valued = false;
        setFlag(flagValue);
    }

    /// sets the option value from rawValue
    virtual void configureWith(const SBuf &rawValue) const override
    {
        assert(recipient_);
        recipient_->configured = true;
        recipient_->valued = true;
        import(rawValue);
    }

    virtual void print(std::ostream &os) const override { if (valued()) os << recipient_->value; }

private:
    void import(const SBuf &rawValue) const { recipient_->value = rawValue; }
    void setFlag(bool) const { /*leave recipient_->value as is*/}

    // The "mutable" specifier demarcates set-once Option kind/behavior from the
    // ever-changing recipient of the actual admin-configured option value.
    mutable Recipient *recipient_ = nullptr; ///< parsing results storage
};

// Links an Option with its option/flag name(s), such as --enable-foo[=value], --disable-foo, or -x[=value].
class OptionName
{
public:
    OptionName(const Option *, const char *on, const char *off = nullptr);

    /// whether name is one of the Option names
    bool has(const SBuf &name) const;

    const Option *option;
    const char *enable; ///< an option/flag name, turning this Option on
    const char *disable; ///< an option/flag name, resetting this Option to a default value
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

template <>
inline void
BooleanOption::setFlag(bool flagValue) const
{
    recipient_->value = flagValue;
}

typedef std::vector<OptionName> Options;

/// parses the flags part of the being-parsed ACL, filling Option values
/// \param options options supported by the ACL as a whole (e.g., -n)
void ParseFlags(const Options &options);

/* handy for Class::options() defaults */
const Options &NoOptions(); ///< \returns an empty Options container

/// Base class for ACL-line-specific options.
/// Create a kid for each ACL which supports a unique set of line options.
class LineOptions
{
public:
    virtual ~LineOptions() {}
    /// \returns (linked) 'line' Options supported by an ACL
    virtual const Acl::Options &options() { return Acl::NoOptions(); }
    /// resets parsed option value(s)
    virtual void reset() = 0;
};

/// Line options for ACL supporting case insensitivity (-i,+i flags).
class CaseLineOptions : public LineOptions
{
public:
    virtual const Acl::Options &options() override;
    virtual void reset() override { caseInsensitive = Acl::BooleanOptionValue(); }
    bool isCaseInsensitive() const { return caseInsensitive.configured && caseInsensitive.value; }

private:
    Acl::BooleanOptionValue caseInsensitive;
};

} // namespace Acl

std::ostream &operator <<(std::ostream &os, const Acl::Option &option);
std::ostream &operator <<(std::ostream &os, const Acl::Options &options);

#endif /* SQUID_ACL_OPTIONS_H */

