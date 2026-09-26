/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "error/Detail.h"
#include "HttpRequest.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

/// details an error by tying it to a uniquely named circumstance
class NamedErrorDetail: public ErrorDetail
{
public:
    // convert from c-string to SBuf to simplify creation and optimize usage
    /// \param aName must not contain characters that require quoting in access logs or HTML
    explicit NamedErrorDetail(const char *aName): name(aName) {}

    /* ErrorDetail API */
    SBuf brief() const override { return name; }
    SBuf verbose(const HttpRequestPointer &) const override { return name; }

private:
    /// distinguishes us from all other NamedErrorDetail objects
    SBuf name;
};

/* ErrorDetail */

std::ostream &
operator <<(std::ostream &os, const ErrorDetail &detail)
{
    os << detail.brief();
    return os;
}

std::ostream &
operator <<(std::ostream &os, const ErrorDetail::Pointer &detail)
{
    if (detail)
        os << *detail;
    else
        os << "[no details]";
    return os;
}

#if USE_OPENSSL
void
StoreErrorDetail(SSL *ssl, const ErrorDetail::Pointer &d)
{
    std::unique_ptr<ErrorDetail::Pointer> detail(new ErrorDetail::Pointer(d));
    if (SSL_set_ex_data(ssl, ssl_ex_index_ssl_error_detail, detail.get()))
        detail.release();
    else
        debugs(83, 2, "WARNING: Failed to store error detail: " << *detail << Ssl::ReportAndForgetErrors);
}
#endif // USE_OPENSSL

/* NamedErrorDetail */

ErrorDetail::Pointer
MakeNamedErrorDetail(const char *name)
{
    return new NamedErrorDetail(name);
}

