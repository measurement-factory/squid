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

#include "Instance.h"
#include "ipc/forward.h"
#include "ipc/Port.h"
#include "mgr/forward.h"
#include "sbuf/SBuf.h"
#if SQUID_SNMP
#include "snmp/forward.h"
#endif

#include <map>

namespace Ipc
{

class StrandCoord;

// TODO: Move to src/ as StrandJob.
/// Receives coordination messages on behalf of its process or thread
class Strand: public Port
{
    CBDATA_CHILD(Strand);

public:
    explicit Strand(const std::optional<SBuf> &aTag);

    // TODO: Name TypedMsgHdr raw type instead of using `int`
    using MessageHandler = void (*)(const TypedMsgHdr &);
    /// instructs where to forward TypedMsgHdr messages of a given type
    void configureMessageHandler(MessageType, MessageHandler);

    void start() override; // Port (AsyncJob) API

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

private:
    /// allows mtFindStrand queries to find this strand
    /// \sa TagStrand()
    const std::optional<SBuf> tag;

    /// our self-registration task; see Strand::registerSelf()
    Instance::OptionalStartupActivityTracker selfRegistrationTracker;

    std::map<int, MessageHandler> messageHandlers;

    bool isRegistered; ///< whether Coordinator ACKed registration

private:
    Strand(const Strand&); // not implemented
    Strand& operator =(const Strand&); // not implemented
};

}

#endif /* SQUID_IPC_STRAND_H */

