/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_IPC_MESSAGES_H
#define SQUID_IPC_MESSAGES_H

/** Declarations used by various IPC messages */

namespace Ipc
{

/// message class identifier
typedef enum { mtNone = 0, ///< unspecified or unknown message kind; unused on the wire

               mtRegisterStrand, ///< notifies about our strand existence
               mtStrandRegistered, ///< acknowledges mtRegisterStrand acceptance

               mtFindStrand, ///< a worker requests a strand from Coordinator
               mtStrandReady, ///< an mtFindStrand answer: the strand exists and should be usable

               mtSharedListenRequest,
               mtSharedListenResponse,

               mtIpcIoNotification,

               mtCollapsedForwardingNotification,

               mtCacheMgrRequest,
               mtCacheMgrResponse,

#if SQUID_SNMP
               mtSnmpRequest,
               mtSnmpResponse,
#endif

               /// The sending kid have itself reached and now waits for other
               /// kids to reach the same synchronization barrier. For now, only
               /// one such synchronization point is supported per Squid
               /// instance lifetime. \sa mtSynchronizationResponse
               mtSynchronizationRequest,

               /// Coordinator sends this message when all kids have sent their
               /// mtSynchronizationRequest and, hence, may now cross the
               /// corresponding synchronization barrier.
               mtSynchronizationResponse,

               /// The sending kid has completed all its startup activities.
               mtKidCompletedStartup,

               mtEnd ///< for message kind range checks; unused on the wire
             } MessageType;

} // namespace Ipc;

#endif /* SQUID_IPC_MESSAGES_H */

