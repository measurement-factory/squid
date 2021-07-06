/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/SslError.h"
#include "acl/SslErrorData.h"
#include "client_side.h"
#include "http/Stream.h"
#include "ssl/ServerBump.h"

int
ACLSslErrorStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    const Security::CertErrors *sslErrors = nullptr;
    if (checklist->sslErrors)
        sslErrors = checklist->sslErrors;
    else if (checklist->conn() && checklist->conn()->serverBump())
        sslErrors = checklist->conn()->serverBump()->sslErrors();

    return data->match (sslErrors);
}

