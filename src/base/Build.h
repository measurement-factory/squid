/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_BUILD_H
#define SQUID_BASE_BUILD_H


#ifdef __ICC
// Intel compiler defines both _MSC_VER and __GNUC__ so it must be first
#define SuspendCompilerGeneratedDeprecationWarnings()   \
    _Pragma("warning (push)")                            \
    _Pragma("warning (disable:1478 1786)")

#define ResumeCompilerGeneratedDeprecationWarnings()    \
    _Pragma("warning (pop)")

#elif defined(_MSC_VER)
#define SuspendCompilerGeneratedDeprecationWarnings()   \
    __pragma(warning (push))                            \
    __pragma(warning (disable:4996))

#define ResumeCompilerGeneratedDeprecationWarnings()  \
    __pragma(warning (pop))

#elif defined(__GNUC__)
// This is works for both clang and gcc 4.5 or later.
#define SuspendCompilerGeneratedDeprecationWarnings()                 \
    _Pragma("GCC diagnostic push")                                      \
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

#define ResumeCompilerGeneratedDeprecationWarnings()  \
    _Pragma("GCC diagnostic pop")

#elif defined(__SUNPRO_C)
#define SuspendCompilerGeneratedDeprecationWarnings()          \
    _Pragma("error_messages (off,symdeprecated,symdeprecated2)")

#define ResumeCompilerGeneratedDeprecationWarnings()          \
    _Pragma("error_messages (on,symdeprecated,symdeprecated2)")

#else

/// Macro to temporarily disable compiler "_a_declaration() is deprecated"
/// warnings/errors
#define SuspendCompilerGeneratedDeprecationWarnings()

/// Must be called always after a SuspendCompilerGeneratedDeprecationWarnings
/// call to re-enable compiler deprecation warnings.
#define ResumeCompilerGeneratedDeprecationWarnings()

#endif

#endif
