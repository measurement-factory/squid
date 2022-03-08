/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
    // We use step1 for transactions not subject to ssl_bump rules (if any) and
    // for transactions/contexts that lack/lost access to SslBump info.
    auto currentSslBumpStep = XactionStep::tlsBump1;

    if (const auto mgr = checklist->conn()) {
        if (const auto serverBump = mgr->serverBump())
            currentSslBumpStep = serverBump->currentStep();
    }

    if (data->match(currentSslBumpStep))
        return 1;
#endif // USE_OPENSSL

    if (data->match(XactionStep::generatingConnect)) {
        if (!checklist->request)
            return 0; // we have warned about the missing request earlier

        if (!checklist->request->masterXaction) {
            debugs(28, DBG_IMPORTANT, "ERROR: Squid BUG: at_step GeneratingCONNECT ACL is missing master transaction info. Assuming mismatch.");
            return 0;
        }

        return checklist->request->masterXaction->generatingConnect ? 1 : 0;
    }

    return 0;
}

