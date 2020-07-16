/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS io management */

#include "squid.h"
#include "fde.h"
#include "security/Io.h"

namespace Security {
    template <typename Fun>
    static IoResult GuardedIo(Comm::Connection &, ErrorCode, Fun);
    static void PrepForIo();

    typedef SessionPointer::element_type *ConnectionPointer;
}

/// the steps necessary to perform before the upcoming TLS I/O
/// to correctly interpret/detail the outcome of that I/O
static void
Security::PrepForIo()
{
#if USE_OPENSSL
    // flush earlier errors that some call forgot to extract, so that we will
    // only get the error(s) specific to the upcoming I/O operation
    while (const auto errorToForget = ERR_get_error())
        debugs(83, 7, "forgot " << asHex(errorToForget));
#endif

    // as the last step, reset errno to know when the I/O operation set it
    errno = 0;
}

/// Calls the given TLS handshake function and analysis its outcome.
/// Handles alert logging and being called without adequate TLS library support.
template <typename Fun>
static Security::IoResult
Security::GuardedIo(Comm::Connection &transport, const ErrorCode topError, Fun ioCall)
{
    assert(transport.isOpen());
    const auto fd = transport.fd;
    auto connection = fd_table[fd].ssl.get();

    PrepForIo();
    const auto callResult = ioCall(connection);
    const auto xerrno = errno;

    debugs(83, 5, callResult << '/' << xerrno << " for TLS connection " <<
           static_cast<void*>(connection) << " over " << transport);

#if USE_OPENSSL
    if (callResult > 0)
        return IoResult(IoResult::ioSuccess);

    const auto ioError = SSL_get_error(connection, callResult);

    // quickly handle common, non-erroneous outcomes
    switch (ioError) {

    case SSL_ERROR_WANT_READ:
        return IoResult(IoResult::ioWantRead);

    case SSL_ERROR_WANT_WRITE:
        return IoResult(IoResult::ioWantWrite);

    default:
        ; // fall through to handle the problem
    }

    // now we know that we are dealing with a real problem; detail it
    const Ssl::ErrorDetail::Pointer errorDetail =
        new Ssl::ErrorDetail(topError, ioError, xerrno);

    IoResult ioResult(errorDetail);

    // collect debugging-related details
    switch (ioError) {
    case SSL_ERROR_SYSCALL:
        if (callResult == 0) {
            ioResult.errorDescription = "peer aborted";
        } else {
            ioResult.errorDescription = "system call failure";
            ioResult.important = (xerrno == ECONNRESET);
        }
        break;

    case SSL_ERROR_ZERO_RETURN:
        // peer sent a "close notify" alert, closing TLS connection for writing
        ioResult.errorDescription = "peer closed";
        ioResult.important = true;
        break;

    default:
        // an ever-increasing number of possible cases but usually SSL_ERROR_SSL
        ioResult.errorDescription = "failure";
        ioResult.important = true;
    }

    return ioResult;

#elif USE_GNUTLS
    if (callResult == GNUTLS_E_SUCCESS) {
        // TODO: Avoid gnutls_*() calls if debugging is off.
        const auto desc = gnutls_session_get_desc(connection);
        debugs(83, 2, "TLS session info: " << desc);
        gnutls_free(desc);
        return IoResult(IoResult::ioSuccess);
    }

    // Debug the TLS connection state so far.
    // TODO: Avoid gnutls_*() calls if debugging is off.
    const auto descIn = gnutls_handshake_get_last_in(connection);
    debugs(83, 2, "handshake IN: " << gnutls_handshake_description_get_name(descIn));
    const auto descOut = gnutls_handshake_get_last_out(connection);
    debugs(83, 2, "handshake OUT: " << gnutls_handshake_description_get_name(descOut));

    if (callResult == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        const auto alert = gnutls_alert_get(connection);
        debugs(83, DBG_IMPORTANT, "WARNING: TLS alert: " << gnutls_alert_get_name(alert));
        // fall through to retry
    }

    if (!gnutls_error_is_fatal(callResult)) {
        const auto reading = gnutls_record_get_direction(connection) == 0;
        return IoResult(reading ? IoResult::ioWantRead : IoResult::ioWantWrite);
    }

    // now we know that we are dealing with a real problem; detail it
    const Ssl::ErrorDetail::Pointer errorDetail =
        new Ssl::ErrorDetail(topError, callResult, xerrno);

    IoResult ioResult(errorDetail);
    ioResult.errorDescription = "failure";
    return ioResult;

#else
    // TLS I/O code path should never be reachable without a TLS/SSL library.
    debugs(1, DBG_CRITICAL, ForceAlert << "BUG: " <<
           "Unexpected TLS I/O in Squid built without a TLS/SSL library");
    assert(false); // we want a stack trace which fatal() does not produce
    return IoResult(nullptr); // not reachable
#endif
}

// TODO: After dropping OpenSSL v1.1.0 support, this and Security::Connect() can
// be simplified further by using SSL_do_handshake() and eliminating lambdas.
Security::IoResult
Security::Accept(Comm::Connection &transport)
{
    return GuardedIo(transport, SQUID_TLS_ERR_ACCEPT, [] (ConnectionPointer tlsConn) -> auto {
#if USE_OPENSSL
        return SSL_accept(tlsConn);
#elif USE_GNUTLS
        return gnutls_handshake(tlsConn);
#else
        return sizeof(tlsConn); // the value is unused; should be unreachable
#endif
    });
}

/// establish a TLS connection over the specified from-Squid transport connection
Security::IoResult
Security::Connect(Comm::Connection &transport)
{
    return GuardedIo(transport, SQUID_TLS_ERR_CONNECT, [] (ConnectionPointer tlsConn) -> auto {
#if USE_OPENSSL
        return SSL_connect(tlsConn);
#elif USE_GNUTLS
        return gnutls_handshake(tlsConn);
#else
        return sizeof(tlsConn); // the value is unused; should be unreachable
#endif
    });
}
