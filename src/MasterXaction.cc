/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "client_side.h"
#include "http/Stream.h"
#include "MasterXaction.h"

InstanceIdDefinitions(MasterXaction, "master", uint64_t);

MasterXaction::MasterXaction(const XactionInitiator anInitiator, ConnStateData *connManager) :
    initiator(anInitiator),
    clientConnectionManager_(connManager),
    clientConnection_(clientConnectionManager_.valid() ? clientConnectionManager_->clientConnection : nullptr)
{};

MasterXaction::MasterXaction(const XactionInitiator anInitiator, Comm::ConnectionPointer aConnection) :
    initiator(anInitiator),
    clientConnection_(aConnection)
{};

Comm::ConnectionPointer
MasterXaction::clientConnection()
{
    return clientConnectionManager_.valid() ? clientConnectionManager_->clientConnection : clientConnection_;
}

void
MasterXaction::setClientConnectionManager(ConnStateData *connManager)
{
    if (!connManager || clientConnectionManager_.valid())
        return;
    clientConnectionManager_ = connManager;
    if (clientConnection_) {
        Must(clientConnection_ == connManager->clientConnection);
        return;
    }
    clientConnection_ = connManager->clientConnection;
}

