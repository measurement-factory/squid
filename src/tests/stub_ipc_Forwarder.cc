/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "ipc/Forwarder.cc"
#include "tests/STUB.h"

#include "ipc/Forwarder.h"
Ipc::Forwarder::Forwarder(Request::Pointer, double): AsyncJob("Ipc::Forwarder"), timeout(0) {STUB}
Ipc::Forwarder::~Forwarder() STUB
void Ipc::Forwarder::start() STUB
bool Ipc::Forwarder::doneAll() const STUB_RETVAL(false)
void Ipc::Forwarder::swanSong() STUB
void Ipc::Forwarder::callException(const std::exception &) STUB
void Ipc::Forwarder::handleError() STUB
void Ipc::Forwarder::handleTimeout() STUB
void Ipc::Forwarder::handleException(const std::exception &) STUB

// TODO: Move into stub_ipc_Inquerer.cc or, together with Ipc::Forwarder above
// and Ipc::TypedMsgHdr elsewhere, into stub_libipc.cc.
#include "ipc/Inquirer.h"
Ipc::Inquirer::Inquirer(Request::Pointer, const StrandCoords &, double): AsyncJob("Ipc::Inquirer"), timeout(0) {STUB}
Ipc::Inquirer::~Inquirer() STUB
void Ipc::Inquirer::cleanup() STUB
void Ipc::Inquirer::start() STUB
void Ipc::Inquirer::inquire() STUB
void Ipc::Inquirer::handleRemoteAck(Response::Pointer) STUB
void Ipc::Inquirer::swanSong() STUB
bool Ipc::Inquirer::doneAll() const STUB_RETVAL(false)
void Ipc::Inquirer::handleException(const std::exception&) STUB
void Ipc::Inquirer::callException(const std::exception&) STUB
void Ipc::Inquirer::HandleRemoteAck(const Response&) STUB
void Ipc::Inquirer::removeTimeoutEvent() STUB
void Ipc::Inquirer::RequestTimedOut(void*) STUB
void Ipc::Inquirer::requestTimedOut() STUB
const char *Ipc::Inquirer::status() const STUB_RETVAL(nullptr)

