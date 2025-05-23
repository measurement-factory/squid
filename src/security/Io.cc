/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS I/O */

#include "squid.h"
#include "base/IoManip.h"
#include "fde.h"
#include "security/Io.h"
#include "ssl/gadgets.h"

namespace Security {

template <typename Fun>
static IoResult Handshake(Comm::Connection &, ErrorCode, Fun);
static void PrepForIo();

typedef SessionPointer::element_type *ConnectionPointer;

} // namespace Security

/// common part of printGist() and printWithExtras()
void
Security::IoResult::printDescription(std::ostream &os) const
{
    const char *strCat = nullptr;
    switch (category) {
    case ioSuccess:
        strCat = "success";
        break;
    case ioWantRead:
        strCat = "want-read";
        break;
    case ioWantWrite:
        strCat = "want-write";
        break;
    case ioError:
        strCat = errorDescription;
        break;
    }
    os << (strCat ? strCat : "unknown");
}

void
Security::IoResult::printGist(std::ostream &os) const
{
    printDescription(os);
    if (important)
        os << ", important";
    // no errorDetail in this summary output
}

void
Security::IoResult::printWithExtras(std::ostream &os) const
{
    printDescription(os);
    if (errorDetail)
        os << Debug::Extra << "error detail: " << errorDetail;
    // this->important flag may affect caller debugs() level, but the flag
    // itself is not reported to the admin explicitly
}

// TODO: Replace high-level ERR_get_error() calls with ForgetErrors() calls or
// exceptions carrying ReportAndForgetErrors() reports.
void
Security::ForgetErrors()
{
#if USE_OPENSSL
    Ssl::ForgetErrors();
#endif
}

/// the steps necessary to perform before the upcoming TLS I/O
/// to correctly interpret/detail the outcome of that I/O
static void
Security::PrepForIo()
{
    // flush earlier errors that some call forgot to extract, so that we will
    // only get the error(s) specific to the upcoming I/O operation
    ForgetErrors();

    // as the last step, reset errno to know when the I/O operation set it
    errno = 0;
}

/// Calls the given TLS handshake function and analysis its outcome.
/// Handles alert logging and being called without adequate TLS library support.
template <typename Fun>
static Security::IoResult
Security::Handshake(Comm::Connection &transport, const ErrorCode topError, Fun ioCall)
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
    ErrorDetail::Pointer errorDetail;
    if (const auto oldDetail = SSL_get_ex_data(connection, ssl_ex_index_ssl_error_detail)) {
        errorDetail = *static_cast<ErrorDetail::Pointer*>(oldDetail);
    } else {
        errorDetail = new ErrorDetail(topError, ioError, xerrno);
        if (const auto serverCert = SSL_get_peer_certificate(connection))
            errorDetail->setPeerCertificate(CertPointer(serverCert));
    }
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

#elif HAVE_LIBGNUTLS
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
    const ErrorDetail::Pointer errorDetail =
        new ErrorDetail(topError, callResult, xerrno);

    IoResult ioResult(errorDetail);
    ioResult.errorDescription = "failure";
    return ioResult;

#else
    (void)topError;
    // TLS I/O code path should never be reachable without a TLS/SSL library.
    debugs(1, DBG_CRITICAL, ForceAlert << "ERROR: Squid BUG: " <<
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
    return Handshake(transport, SQUID_TLS_ERR_ACCEPT, [] (ConnectionPointer tlsConn) {
#if USE_OPENSSL
        return SSL_accept(tlsConn);
#elif HAVE_LIBGNUTLS
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
    return Handshake(transport, SQUID_TLS_ERR_CONNECT, [] (ConnectionPointer tlsConn) {
#if USE_OPENSSL
        return SSL_connect(tlsConn);
#elif HAVE_LIBGNUTLS
        return gnutls_handshake(tlsConn);
#else
        return sizeof(tlsConn); // the value is unused; should be unreachable
#endif
    });
}

