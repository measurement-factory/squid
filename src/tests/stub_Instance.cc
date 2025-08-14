/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "Instance.cc"
#include "tests/STUB.h"

#include "Instance.h"
Instance::StartupActivityTracker::StartupActivityTracker(const ScopedId &) STUB
Instance::StartupActivityTracker::~StartupActivityTracker() STUB
Instance::StartupActivityTracker::StartupActivityTracker(StartupActivityTracker &&) STUB
void Instance::OptionalStartupActivityTracker::start(const ScopedId &) STUB_NOP
void Instance::OptionalStartupActivityTracker::finish() STUB_NOP
void Instance::ThrowIfAlreadyRunning() STUB
void Instance::WriteOurPid() STUB
pid_t Instance::Other() STUB_RETVAL({})
void Instance::NotifyWhenStartedStartupActivitiesFinished(const AsyncCallPointer &) STUB
bool Instance::Starting() STUB

