/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_OPENSSL

#include "acl/AtStep.h"
#include "acl/AtStepData.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "http/Stream.h"
#include "ssl/ServerBump.h"

int
ACLAtStepStrategy::match (ACLData<Ssl::BumpStep> * &data, ACLFilledChecklist *checklist)
{
    if (const auto mgr = checklist->clientConnectionManager()) {
        if (const auto bump = mgr->serverBump())
            return data->match(bump->step);
    }
    return data->match(Ssl::bumpStep1);
}

#endif /* USE_OPENSSL */

