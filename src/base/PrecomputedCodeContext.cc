/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "base/PrecomputedCodeContext.h"
#include "MasterXaction.h"
#include "sbuf/Stream.h"


PrecomputedCodeContext::PrecomputedCodeContext(const char *gist, const SBuf &detail, const MasterXaction::Pointer &mx): gist_(gist),
    detail_(detail),
    masterXactionDetail_(mx ? ToSBuf(mx->id) : SBuf())
{}

ScopedId
PrecomputedCodeContext::codeContextGist() const
{
    // See also: AnyP::PortCfg::codeContextGist().
    return ScopedId(gist_);
}

std::ostream &
PrecomputedCodeContext::detailCodeContext(std::ostream &os) const
{
    os << Debug::Extra << detail_;
    if (!masterXactionDetail_.isEmpty())
        os << Debug::Extra << "current master transaction: " << masterXactionDetail_;
    return os;
}

