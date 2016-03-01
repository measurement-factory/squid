/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MASTERXACTION_H
#define SQUID_SRC_MASTERXACTION_H

#include "anyp/forward.h"
#include "base/InstanceId.h"
#include "base/Lock.h"
#include "comm/forward.h"

/** Master transaction details.
 *
 * Aggregates historical data from individual related protocol-specific
 * transactions such as an HTTP client transaction and the corresponding
 * HTTP or FTP server transaction.
 *
 * Individual transaction information worth sending or logging should be
 * recorded here, ideally without exposing other master transaction users
 * to internal details of individual transactions. For example, storing an
 * HTTP client IP address is a good idea but storing a pointer to some
 * client-side job which maintains that address is not.
 *
 * A master transaction is created by a newly accepted client connection,
 * a new request on the existing client connection, or an internal request
 * generated by Squid. All client-side protocols, including HTTP, HTCP, ICP,
 * and SNMP will eventually create master transactions.
 *
 * A master transaction is auto-destroyed when its last user is gone.
 */
class MasterXaction : public RefCountable
{
public:
    typedef RefCount<MasterXaction> Pointer;

    /// transaction ID.
    InstanceId<MasterXaction> id;

    /// the listening port which originated this transaction
    AnyP::PortCfgPointer squidPort;

    /// the client TCP connection which originated this transaction
    Comm::ConnectionPointer tcpClient;

    // TODO: add state from other Jobs in the transaction
};

#endif /* SQUID_SRC_MASTERXACTION_H */

