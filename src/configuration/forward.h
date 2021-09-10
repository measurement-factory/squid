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
class Preprocessor;
class PreprocessedDirective;

// XXX: Document
bool AvoidFullReconfiguration(const char *filename);
int PerformFullReconfiguration();
int Configure(const char *filename);

} // namespace Configuration


#endif /* SQUID_SRC_CONFIGURATION_FORWARD_H */

