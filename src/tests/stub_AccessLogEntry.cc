/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"

#define STUB_API "AccessLogEntry.cc"
#include "tests/STUB.h"

#if FOLLOW_X_FORWARDED_FOR
const Ip::Address& AccessLogEntry::furthestClientAddress() const STUB_RETREF(Ip::Address)
#endif
const Ip::Address& AccessLogEntry::clientAddr() const STUB_RETREF(Ip::Address)
const Ip::Address& AccessLogEntry::myAddr() const STUB_RETREF(Ip::Address)

