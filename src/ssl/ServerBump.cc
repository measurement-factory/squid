/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#include "squid.h"
#include "anyp/Uri.h"
#include "client_side.h"
#include "client_side_request.h"
#include "FwdState.h"
#include "http/Stream.h"
#include "ssl/ServerBump.h"
#include "Store.h"
#include "StoreClient.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, ServerBump);

Ssl::ServerBump::ServerBump(const char * const reason)
{
    assert(at(XactionStep::tlsBump1));
    assert(reason);
    debugs(33, 4, "starting step1 for " << reason);
}

Ssl::ServerBump::~ServerBump()
{
    debugs(33, 4, step_);
    clearStoreEntry();
}

StoreEntry *
Ssl::ServerBump::sawError() const
{
    return (entry_ && !entry_->isEmpty()) ? entry_ : nullptr;
}

void
Ssl::ServerBump::attachServerSession(const Security::SessionPointer &s)
{
    serverSession = s;
}

Security::CertErrors *
Ssl::ServerBump::sslErrors() const
{
    if (!serverSession)
        return nullptr;

    return static_cast<Security::CertErrors*>(SSL_get_ex_data(serverSession.get(), ssl_ex_index_ssl_errors));
}

Ssl::BumpMode
Ssl::ServerBump::actionAfterNoRulesMatched() const
{
    if (at(XactionStep::tlsBump1)) {
        debugs(85, 3, "splicing at no-match step1");
        return bumpSplice;
    }

    // XXX: replace applied_/requested_ with actions_

    assert(at(XactionStep::tlsBump2) || at(XactionStep::tlsBump3));
    // previousStep action determines what happens when no rules match now
    const auto previousStep = at(XactionStep::tlsBump2) ? requested_.step1 : requested_.step2;
    if (previousStep == bumpStare) {
        debugs(85, 3, "bumping at no-match step because the previous step stared");
        return bumpBump;
    }
    // If previousStep was neither bumpStare nor bumpPeek, then that
    // step would have been the last/final one, and no ssl_bump rules would be
    // evaluated now.
    assert(previousStep == bumpPeek);
    debugs(85, 3, "splicing at no-match step because the previous step peeked");
    return bumpSplice;
}

void
Ssl::ServerBump::noteNeed(const BumpMode mode)
{
    debugs(83, 3, mode << " at " << step_);
    if (at(XactionStep::tlsBump1)) {
        requested_.step1 = mode;
    } else if (at(XactionStep::tlsBump2)) {
        requested_.step2 = mode;
    } else {
        assert(at(XactionStep::tlsBump3));
        requested_.step3 = mode;
    }
}

Ssl::BumpMode
Ssl::ServerBump::currentNeed() const
{
    auto mode = Ssl::bumpEnd;
    if (at(XactionStep::tlsBump1)) {
        mode = requested_.step1;
    } else if (at(XactionStep::tlsBump2)) {
        mode = requested_.step2;
    } else {
        assert(at(XactionStep::tlsBump3));
        mode = requested_.step3;
    }
    debugs(83, 5, mode << " at " << step_);
    // TODO: assert(mode != Ssl::bumpEnd);
    return mode;
}

void
Ssl::ServerBump::noteStepStart(const XactionStep step)
{
    // step1 cannot be restarted or explicitly started
    assert(step != XactionStep::tlsBump1);

    if (step == step_) {
        // TODO: Remove/assert if/that this is impossible.
        debugs(83, 5, "repeating " << step_);
        // TODO: Clear stale requested_.stepN!
        return;
    }

    debugs(83, 5, step);
    step_ = step;
}

StoreEntry *
Ssl::ServerBump::startStep3(ClientHttpRequest &http)
{
    assert(at(XactionStep::tlsBump2)); // no restarts and no skipped steps
    step_ = XactionStep::tlsBump3;

    const auto newEntry = createStoreEntry(http);
    debugs(83, 5, *newEntry);
    return newEntry;
}

void
Ssl::ServerBump::noteFinished(const char * const reason)
{
    debugs(83, 5, "done at " << step_ << " for " << reason);
    step_ = XactionStep::tlsBumpDone; // may already be XactionStep::tlsBumpDone
}

StoreEntry *
Ssl::ServerBump::createStoreEntry(ClientHttpRequest &http)
{
    assert(!entry_);
    const auto request2_XXX = http.request;
    assert(request2_XXX);

    // XXX: Performance regression. c_str() reallocates
    auto uriBuf = request2_XXX->effectiveRequestUri();
    const auto uri = uriBuf.c_str();

    const auto newEntry = storeCreateEntry(uri, uri, request2_XXX->flags, request2_XXX->method);
    useStoreEntry(http, newEntry);
    return newEntry;
}

void
Ssl::ServerBump::clearStoreEntry()
{
    if (entry_) {
        assert(sc_);
        storeUnregister(sc_, entry_, this);
        sc_ = nullptr;
        entry_->unlock("Ssl::ServerBump");
        entry_ = nullptr;
    }
}

void
Ssl::ServerBump::useStoreEntry(ClientHttpRequest &http, StoreEntry * const newEntry)
{
    assert(newEntry);

    assert(entry_ != newEntry);
    clearStoreEntry(); // if any

    assert(!entry_);
    entry_ = newEntry;
    entry_->lock("Ssl::ServerBump");
    assert(!sc_);
    sc_ = storeClientListAdd(entry_, this);
#if USE_DELAY_POOLS
    sc_->setDelayId(DelayId::DelayClient(&http));
#else
    (void)http;
#endif
    debugs(33, 4, *entry_);
}

void
Ssl::ServerBump::print(std::ostream &os) const
{
    // report known need for each step, ignoring future steps:
    // SslBumpStep1 -- step1 before ssl_bump matching
    // SslBumpStep1:peek -- step1 after matching an "ssl_bump peek" rule
    // SslBumpStep2:peek -- step2 before ssl_bump matching
    // SslBumpStepDone:peek,splice -- honored a splice rule during step2
    // TODO: If future steps are impossible, stop ignoring them.
    // TODO: If step retries are possible, make sure they clear stale needs.

    os << step_;

    if (requested_.step1 != Ssl::bumpEnd) {
        os << ':';
        os << requested_.step1;
        if (at(XactionStep::tlsBump1))
            return;
    }

    if (requested_.step2 != Ssl::bumpEnd) {
        os << ',';
        os << requested_.step2;
        if (at(XactionStep::tlsBump2))
            return;
    }

    if (requested_.step3 != Ssl::bumpEnd) {
        os << ',';
        os << requested_.step3;
        if (at(XactionStep::tlsBump3))
            return;
    }
}

/* Ssl::ServerBump::Actions */

Ssl::ServerBump::Actions::Actions():
    step1(Ssl::bumpEnd),
    step2(Ssl::bumpEnd),
    step3(Ssl::bumpEnd)
{
}