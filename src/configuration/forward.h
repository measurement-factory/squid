/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CONFIGURATION_FORWARD_H
#define SQUID_SRC_CONFIGURATION_FORWARD_H

namespace Configuration {

class Location;
class Preprocessor;
class PreprocessedDirective;

/// Initial configuration: Parse (and typically apply) directives in filename.
int Configure(const char *filename);

/// Whether the caller should commit to performing harsh reconfiguration,
/// restarting major services and calling PerformFullReconfiguration().
/// Side effect: Preprocesses configuration files.
/// Side effect: Performs smooth reconfiguration (if possible).
bool ShouldPerformHarshReconfiguration(const char *filename);

/// Processes all configuration directives, both changed and unchanged ones. The
/// list of (preprocessed) configuration directives is computed during an
/// earlier ShouldPerformHarshReconfiguration() call that returned true.
int PerformFullReconfiguration();

} // namespace Configuration

#endif /* SQUID_SRC_CONFIGURATION_FORWARD_H */

