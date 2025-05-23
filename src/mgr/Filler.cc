/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "comm/Connection.h"
#include "ipc/RequestId.h"
#include "mgr/Filler.h"
#include "mgr/Response.h"
#include "Store.h"

CBDATA_NAMESPACED_CLASS_INIT(Mgr, Filler);

Mgr::Filler::Filler(const Action::Pointer &anAction, const Comm::ConnectionPointer &conn,
                    const Ipc::RequestId aRequestId):
    StoreToCommWriter(conn, anAction->createStoreEntry()),
    action(anAction),
    requestId(aRequestId)
{
    debugs(16, 5, conn << " action: " << action);
}

void
Mgr::Filler::start()
{
    debugs(16, 5, MYNAME);
    Must(requestId != 0);
    Must(action != nullptr);

    StoreToCommWriter::start();
    action->run(entry, false);
}

void
Mgr::Filler::swanSong()
{
    debugs(16, 5, MYNAME);
    action->sendResponse(requestId);
    StoreToCommWriter::swanSong();
}

