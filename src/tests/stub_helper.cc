/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "helper.h"

#define STUB_API "helper.cc"
#include "tests/STUB.h"

void helperSubmit(const helper::Pointer &, const char *, HLPCB *, void *) STUB
void helperStatefulSubmit(const statefulhelper::Pointer &, const char *, HLPCB *, void *, helper_stateful_server *) STUB
helper::~helper() STUB
void helper::packStatsInto(Packable *p, const char *label) const STUB

void helperShutdown(const helper::Pointer &) STUB
void helperStatefulShutdown(const statefulhelper::Pointer &) STUB
void helperOpenServers(const helper::Pointer &) STUB
void helperStatefulOpenServers(const statefulhelper::Pointer &) STUB
helper_stateful_server *helperStatefulDefer(const statefulhelper::Pointer &) STUB_RETVAL(NULL)
void helperStatefulReleaseServer(helper_stateful_server * srv) STUB

