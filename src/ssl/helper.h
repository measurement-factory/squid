/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_HELPER_H
#define SQUID_SRC_SSL_HELPER_H

#if USE_OPENSSL

#include "base/AsyncJobCalls.h"
#include "base/ClpMap.h"
#include "../helper.h"
#include "helper/forward.h"
#include "sbuf/Algorithms.h"
#include "security/forward.h"
#include "ssl/cert_validate_message.h"
#include "ssl/crtd_message.h"

namespace Ssl
{
#if USE_SSL_CRTD

class GeneratorRequest;

/**
 * Set of thread for ssl_crtd. This class is singleton.
 * This class use helper structure for threads management.
 */
class Helper: public ::Helper::Client
{
public:
    using Pointer = RefCount<Helper>;

    /// query:GeneratorRequest map
    using GeneratorRequests = std::unordered_map<SBuf, GeneratorRequest*>;

    static void Init(); ///< Init helper structure.
    static void Shutdown(); ///< Shutdown helper structure.
    static void Reconfigure(); ///< Reconfigure helper structure.
    /// Submit crtd message to external crtd server.
    static void Submit(CrtdMessage const & message, HLPCB * callback, void *data);

    /// \copydoc helper::Make()
    static Pointer Make(const char *name) { return new Helper(name); }

    explicit Helper(const char * const name): Helper::Client(name) {}

    /* Helper::Client API */
    void callBack(::Helper::Xaction &) override;

private:
    static Pointer ssl_crtd; ///< helper instance

    /// pending Helper requests (to all certificate generator helpers combined)
    GeneratorRequests generatorRequests;
};
#endif

class CertValidationRequest;
class CertValidationResponse;
class CertValidationHelper
{
public:
    using Answer = CertValidationResponse::Pointer;
    using Callback = AsyncCallback<Answer>;

    typedef void CVHCB(void *, Ssl::CertValidationResponse const &);
    static void Init(); ///< Init helper structure.
    static void Shutdown(); ///< Shutdown helper structure.
    static void Reconfigure(); ///< Reconfigure helper structure
    /// Submit crtd request message to external crtd server.
    static void Submit(const Ssl::CertValidationRequest &, const Callback &);
private:
    static ::Helper::ClientPointer ssl_crt_validator; ///< helper for management of ssl_crtd.
public:
    typedef ClpMap<SBuf, CertValidationResponse::Pointer, CertValidationResponse::MemoryUsedByResponse> CacheType;
    static CacheType *HelperCache; ///< cache for cert validation helper
};

} //namespace Ssl

#endif /* USE_OPENSSL */
#endif /* SQUID_SRC_SSL_HELPER_H */

