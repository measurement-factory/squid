/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CONFIGOPTION_H
#define SQUID_SRC_CONFIGOPTION_H

#include "configuration/forward.h"

#include <iosfwd>
#include <vector>

class StoreEntry;

namespace Configuration {

/// Interface for basic/low-level manipulation of a squid.conf directive value.
/// Hides T's declarations from squid.conf parsing/reconfiguring/reporting code.
///
/// Implementations/specializations must not modify the current configuration
/// (i.e. the Config objects and similar/related global state). To facilitate
/// reuse, implementations/specializations should also be independent from any
/// specific configuration directive name and its squid.conf location.
template <class T>
class Component
{
public:
    /* specialize these when adding "TYPE: T" to cf.data.pre */

    /// parses a given directive using the given parser, storing the result in T
    static void Parse(T &, ConfigParser &);

    /// reports configuration of a T instance using squid.conf format
    static void Print(std::ostream &, const T &, const char *directiveName);

    /// restores initial T instance state (i.e. state prior to Parse() calls),
    /// freeing resources allocated by previous matching Parse() calls
    static void Reset(T &);

    /// Prepares for smooth reconfiguration of features tied to T directives.
    /// These directives may not be present in the current configuration and/or
    /// may not be present in the updated configuration. In the latter case,
    /// there will be no corresponding Reconfigure() calls. This method is
    /// called before any Reconfigure() calls.
    /// \sa FinishSmoothReconfiguration() and StartSmoothReconfigurationOfComponents()
    static void StartSmoothReconfiguration(SmoothReconfiguration &);

    /// Smoothly reconfigures a given directive. All such calls for T directives
    /// are preceded by a single StartSmoothReconfiguration() call and followed
    /// by a single FinishSmoothReconfiguration() call.
    static void Reconfigure(SmoothReconfiguration &, T &, ConfigParser &);

    /// Finishes smooth reconfiguration of features tied to T directives.
    /// \sa StartSmoothReconfiguration() and FinishSmoothReconfigurationOfComponents()
    static void FinishSmoothReconfiguration(SmoothReconfiguration &);
};

} // namespace Configuration

/*
 * Deprecated squid.conf option wrappers used by cache_dir handling code. These
 * classes are similar to Configuration::Component<T>, but they merge T with T
 * parsing API, making them ill-suited for handling SquidConfig data members
 * with built-in C++ types and, more importantly, forcing SquidConfig users to
 * know about parsing/dumping/freeing capabilities of each SquidConfig
 * component. They also do not hide T details from the generic squid.conf
 * parsing code -- one has to provide a type-specific parse_T() for each T.
 */

class ConfigOption
{

public:
    virtual ~ConfigOption() {}

    virtual bool parse(char const *option, const char *value, int reconfiguring) = 0;
    virtual void dump(StoreEntry * e) const = 0;
};

class ConfigOptionVector : public ConfigOption
{

public:
    ~ConfigOptionVector() override;
    bool parse(char const *option, const char *value, int reconfiguring) override;
    void dump(StoreEntry * e) const override;
    std::vector<ConfigOption *>options;
};

template <class C>
class ConfigOptionAdapter : public ConfigOption
{

public:
    ConfigOptionAdapter(C& theObject, bool (C::*parseFP)(char const *option, const char *value, int reconfiguring), void (C::*dumpFP)(StoreEntry * e) const) : object(theObject), parser(parseFP), dumper(dumpFP) {}

    bool parse(char const *option, const char *value, int isaReconf) override {
        if (parser)
            return (object.*parser)(option, value, isaReconf);

        return false;
    }

    void dump(StoreEntry * e) const override {
        if (dumper)
            (object.*dumper)(e);
    }

private:
    C &object;
    bool (C::*parser)(char const *option, const char *value, int reconfiguring) ;
    void (C::*dumper)(StoreEntry * e) const;
};

#endif /* SQUID_SRC_CONFIGOPTION_H */

