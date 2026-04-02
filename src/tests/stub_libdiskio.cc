/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "DiskIO/libdiskio.la"
#include "tests/STUB.h"

#include <vector>

// #include "DiskIO/DiskFile.h"
#include "DiskIO/DiskIOModule.h"
void DiskIOModule::SetupAllModules() STUB
void DiskIOModule::ModuleAdd(DiskIOModule &) STUB
void DiskIOModule::FreeAllModules() STUB
DiskIOModule *DiskIOModule::Find(char const *) STUB_RETVAL(nullptr)
DiskIOModule *DiskIOModule::FindDefault() STUB_RETVAL(nullptr)
DiskIOModule::DiskIOModule() {STUB}

// #include "DiskIO/DiskIOStrategy.h"
// #include "DiskIO/DiskIORequestor.h"
#include "DiskIO/ReadRequest.h"
ReadRequest::ReadRequest(char *, off_t, size_t) {STUB}

#include "DiskIO/WriteRequest.h"
WriteRequest::WriteRequest(char const *, off_t, size_t, FREE *) {STUB}

