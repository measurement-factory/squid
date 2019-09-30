/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "acl/AtStep.h"
#include "acl/AtStepData.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "http/Stream.h"
#if USE_OPENSSL
#include "ssl/ServerBump.h"
#endif

int
ACLAtStepStrategy::match(ACLData<XactionStep> * &data, ACLFilledChecklist *checklist)
{
#if USE_OPENSSL
    Ssl::ServerBump *bump = NULL;
    if (checklist->conn() != NULL &&
        (bump = checklist->conn()->serverBump()) &&
        data->match(bump->step))
        return 1;

    // We need the following to cover the case of bumping at SslBump1 step
    // where the connStateData::serverBump() is not build yet.
    // The following also has the meaning that if no bumping preformed
    // or a client-first bumping is applied then the request is remaining
    // at SslBump1 bumping processing step.
    if (data->match(XactionStep::tlsBump1))
        return 1;
#endif

    if (data->match(XactionStep::generatingConnect)) {
        if (!checklist->request)
            return 0; // we have warned about the missing request earlier

        if (!checklist->request->masterXaction) {
            debugs(28, DBG_IMPORTANT, "at_step GeneratingCONNECT ACL is missing master transaction info. Assuming mismatch.");
            return 0;
        }

        return checklist->request->masterXaction->generatingConnect ? 1 : 0;
    }

    return 0;
}

