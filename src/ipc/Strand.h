/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_STRAND_H
#define SQUID_IPC_STRAND_H

#include "ipc/forward.h"
#include "ipc/Port.h"
#include "mgr/forward.h"
#if SQUID_SNMP
#include "snmp/forward.h"
#endif

namespace Ipc
{

class StrandCoord;

/// Receives coordination messages on behalf of its process or thread
class Strand: public Port
{
    CBDATA_CHILD(Strand);

public:
    static Strand &Instance(); ///< the only class instance in existence

    /// Initiates this kid process registration with Coordinator as well as
    /// listening for IPC messages from Coordinator. Repeated calls are safe and
    /// do nothing.
    /// \prec This process is an SMP Squid kid process but is not a Coordinator.
    static void Init();

    Strand();

    void start() override; // Port (AsyncJob) API

    /// Starts waiting for all kids to reach a startup synchronization barrier
    /// maintained by Coordinator. When they do, calls the given callback.
    void barrierWait(const AsyncCallPointer &);

protected:
    void timedout() override; // Port (UsdOp) API
    void receive(const TypedMsgHdr &message) override; // Port API

private:
    void registerSelf(); /// let Coordinator know this strand exists
    void handleRegistrationResponse(const StrandMessage &);
    void handleCacheMgrRequest(const Mgr::Request& request);
    void handleCacheMgrResponse(const Mgr::Response& response);
#if SQUID_SNMP
    void handleSnmpRequest(const Snmp::Request& request);
    void handleSnmpResponse(const Snmp::Response& response);
#endif
    void handleSynchronizationResponse(const SynchronizationResponse &);

private:
    /// a task waiting for other kids to reach the same synchronization point
    AsyncCallPointer synchronizationCallback;

    bool isRegistered; ///< whether Coordinator ACKed registration (unused)

private:
    Strand(const Strand&); // not implemented
    Strand& operator =(const Strand&); // not implemented
};

}

#endif /* SQUID_IPC_STRAND_H */

