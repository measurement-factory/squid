/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SSL_PEEKER_H
#define _SQUID_SSL_PEEKER_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "comm/forward.h"
#include "HttpRequest.h"
#include "ip/Address.h"
#include "security/forward.h"
#include "Store.h"
#include "XactionStep.h"

#include <iosfwd>

class ConnStateData;
class store_client;
class ClientHttpRequest;

namespace Ssl
{

using BumpStep = XactionStep;

/**
 * Maintains bump-server-first related information.
 */
class ServerBump
{
    CBDATA_CLASS(ServerBump);

public:
    /// starts the first SslBump step
    /// \param reason why the caller initiated SslBump processing
    explicit ServerBump(const char *reason);
    ~ServerBump();
    void attachServerSession(const Security::SessionPointer &); ///< Sets the server TLS session object
    const Security::CertErrors *sslErrors() const; ///< SSL [certificate validation] errors

    // TODO: If entry_ may exist before step3, adjust entry_ and related docs.
    // TODO: If entry_ only exists during step3, adjust these step-agnostic methods.

    /// whether there was a successful connection to (and peeking at) the origin server
    bool connectedOk() const {return entry_ && entry_->isEmpty();}

    /// tests whether there was an error on the SslBump path
    /// \returns nil if there was no error
    /// \returns a non-empty StoreEntry if there was an error
    StoreEntry *sawError() const;

    // TODO: Make private?
    /// Creates a StoreEntry for storing Squid-generated errors (when fetching
    /// server certs from a peer). This entry is required by the FwdState API.
    /// The ServerBump object retains a (shared) pointer to the new entry.
    /// \returns the created entry
    StoreEntry *createStoreEntry(ClientHttpRequest &);

    /// TODO: describe
    void clearStoreEntry();

    /// TODO: describe
    void useStoreEntry(ClientHttpRequest &, StoreEntry *);

    /// whether we are currently performing the given processing step
    bool at(const BumpStep step) const { return step_ == step; }

    /// last started processing stage or, after, noteFinished(), tlsBumpDone
    BumpStep currentStep() const { return step_; }

    /// ssl_bump action that matched (explicitly or not) during the last
    /// doCallouts(); thus, the need may change during each step
    /// \returns bumpEnd before the first rule evaluation in doCallouts() and
    /// after noteFinished().
    BumpMode currentNeed() const;

    /// implicit ssl_bump action to use when no ssl_bump rule matched
    BumpMode actionAfterNoRulesMatched() const;

    /// record the new matched (explicitly or not) ssl_bump action
    void noteNeed(BumpMode);

    /// advance to XactionStep::tlsBump3
    /// \returns a freshly created StoreEntry for storing FwdState errors
    StoreEntry *startStep3(ClientHttpRequest &);

    /// advance to the given step; step2 may be skipped
    void noteStepStart(BumpStep);

    /// mark the ending of the current step; stop expecting more noteStepStart()s
    void noteFinished(const char *reason);

    /// reports ServerBump gist (for debugging)
    void print(std::ostream &) const;

    /// HTTPS server certificate. Maybe it is different than the one
    /// it is stored in serverSession object (error SQUID_X509_V_ERR_CERT_CHANGE)
    Security::CertPointer serverCert;

private:
    Security::SessionPointer serverSession; ///< The TLS session object on server side.

    StoreEntry *entry_ = nullptr; ///< for receiving Squid-generated error messages
    store_client *sc_ = nullptr; ///< dummy client to prevent entry_ trimming

    /// SslBump action at each processing step.
    /// XXX: Document Ssl::bumpEnd "default" or, better, block access to unknown values.
    class Actions {
    public:
        Actions();
        BumpMode step1; ///< action at the tlsBump1 step
        BumpMode step2; ///< action at the tlsBump2 step
        BumpMode step3; ///< action at the tlsBump3 step
    };

    /// Actions requested at each SslBump step
    Actions requested_;

    BumpMode currentMode_; ///< the last requested action or Ssl::bumpEnd;

    /// current SslBump processing step or XactionStep::tlsBumpDone
    BumpStep step_ = XactionStep::tlsBump1;
};

/// \copydoc ServerBump::print()
inline std::ostream &operator <<(std::ostream &os, const ServerBump &sb)
{
    sb.print(os);
    return os;
}

} // namespace Ssl

#endif

