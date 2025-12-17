/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/ChecklistFiller.h"
#include "acl/FilledChecklist.h"
#include "MasterXaction.h"
#include "security/CommunicationSecrets.h"
#include "security/KeyLog.h"
#include "security/KeyLogger.h"
#include "security/Session.h"
#include "SquidConfig.h"

#include <ostream>

namespace Security {

/// manages collecting and logging TLS connection secrets to tls_key_log
class KeyLogger
{
public:
    /// reacts to availability of a secret (e.g., CLIENT_TRAFFIC_SECRET_0,
    /// SERVER_HANDSHAKE_TRAFFIC_SECRET, or EXPORTER_SECRET) in NSS
    /// SSLKEYLOGFILE format
    void noteKeyMaterial(const char *);

    /// logs new secrets (if any)
    /// \prec ShouldLogKeys()
    void maybeLog(const Connection &);

private:
    /// connection secrets learned so far
    CommunicationSecrets secrets;
};

} // namespace Security

void
Security::KeyLogger::maybeLog(const Connection &sconn)
{
    const auto records = secrets.exportFormatted(sconn);
    if (!records.isEmpty())
        Config.Log.tlsKeys->record(records);
}

/// whether logging of TLS secrets has been requested and is possible for the
/// given caller
static bool
ShouldLogKeys(const Acl::ChecklistFiller &caller)
{
    if (!Config.Log.tlsKeys)
        return false; // default: admin does not want us to log (implicitly)

    if (!Config.Log.tlsKeys->canLog()) {
        debugs(33, 3, "no: problems with the logging module");
        return false;
    }

    const auto acls = Config.Log.tlsKeys->aclList;
    if (!acls) {
        debugs(33, 7, "yes: no ACLs");
        return true;
    }

    ACLFilledChecklist checklist;
    caller.fillChecklist(checklist);
    if (!checklist.fastCheck(acls).allowed()) {
        debugs(33, 4, "no: admin does not want us to log (explicitly)");
        return false;
    }

    debugs(33, 5, "yes: ACLs matched");
    return true;
}

void
Security::KeyLogger::noteKeyMaterial(const char * const logLine)
{
    assert(logLine);
    secrets.importFormatted(logLine);
    // and wait for maybeLog() via KeyLoggingCheckpoint()
}

#if USE_OPENSSL
/// "free" function for SSL_get_ex_new_index("key_logger")
static void
FreeKeyLogger(void *, void * const ptr, CRYPTO_EX_DATA *, int, long, void *)
{
    delete static_cast<Security::KeyLogger*>(ptr);
}

/// position of KeyLogger storage slot inside Security::Connection "exdata"
static auto
KeyLoggerIndex()
{
    // TODO: Wrap OpenSSL "exdata" API to make it Squid-friendly, including error handling.
    static int index = SSL_get_ex_new_index(0, const_cast<char *>("key_logger"), nullptr, nullptr, &FreeKeyLogger);
    return index;
}

/// an OpenSSL TLS key logging callback (i.e. SSL_CTX_keylog_cb_func)
static void
KeyLoggingCallback(const SSL * const session, const char * const logLine)
{
    SWALLOW_EXCEPTIONS({
        if (auto keyLogger = static_cast<Security::KeyLogger*>(SSL_get_ex_data(session, KeyLoggerIndex())))
            keyLogger->noteKeyMaterial(logLine);
    });
}
#endif /* USE_OPENSSL */

void
Security::EnableKeyLogging(ContextPointer &ctx)
{
#if USE_OPENSSL
    // Optimization: Do not trigger key logging callbacks by default.
    // TODO: This optimization must be disclosed when adding support for smooth
    // reconfiguration: Admins would have to configure tls_key_log (e.g., with a
    // never-matching `!all` ACL) in advance to be able to smoothly enable it
    // later for new TLS connections created with old TLS contexts.
    if (!Config.Log.tlsKeys)
        return;

    Assure(ctx);
#if HAVE_LIBSSL_SSL_CTX_SET_KEYLOG_CALLBACK
    SSL_CTX_set_keylog_callback(ctx.get(), &KeyLoggingCallback);
    // #else KeyLog has already warned about the lack of support for TLS v1.3.
#endif /* HAVE_LIBSSL_SSL_CTX_SET_KEYLOG_CALLBACK */

#else
    (void)ctx;
#endif /* USE_OPENSSL */
}

void
Security::KeyLoggingStart(Connection &sconn, const Acl::ChecklistFiller &caller)
{
    if (!ShouldLogKeys(caller))
        return;

#if USE_OPENSSL
    auto keyLogger = std::make_unique<Security::KeyLogger>();
    keyLogger->maybeLog(sconn);
    if (SSL_set_ex_data(&sconn, KeyLoggerIndex(), keyLogger.get()))
        keyLogger.release();
#else
    (void)sconn;
    (void)caller;
#endif
}

void
Security::KeyLoggingCheckpoint(const Connection &sconn)
{
#if USE_OPENSSL
    if (const auto keyLogger = static_cast<KeyLogger*>(SSL_get_ex_data(&sconn, KeyLoggerIndex())))
        keyLogger->maybeLog(sconn);
#else
    (void)sconn;
#endif
}

