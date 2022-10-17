/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "globals.h"
#include "helper.h"
#include "sbuf/Stream.h"
#include "security/CertError.h"
#include "ssl/cert_validate_message.h"
#include "ssl/Config.h"
#include "ssl/ErrorDetail.h"
#include "ssl/support.h"
#include "util.h"

/// Retrieves the certificates chain used to verify the peer.
/// This is the full chain built by OpenSSL while verifying the server
/// certificate or, if this is not available, the chain sent by server.
/// \return the certificates chain or nil
static STACK_OF(X509) *
PeerValidationCertificatesChain(const Security::SessionPointer &ssl)
{
    assert(ssl);
    // The full chain built by openSSL while verifying the server cert,
    // retrieved from verify callback:
    if (const auto certs = static_cast<STACK_OF(X509) *>(SSL_get_ex_data(ssl.get(), ssl_ex_index_ssl_cert_chain)))
        return certs;

    /// Last resort: certificates chain sent by server
    return SSL_get_peer_cert_chain(ssl.get()); // may be nil
}

void
Ssl::CertValidationMsg::composeRequest(const CertValidationRequest &vcert, const std::string *extras)
{
    body.clear();
    body += Ssl::CertValidationMsg::param_host + "=" + vcert.domainName;

    if (const char *sslVersion = SSL_get_version(vcert.ssl.get()))
        body += "\n" +  Ssl::CertValidationMsg::param_proto_version + "=" + sslVersion;

    if (const char *cipherName = SSL_CIPHER_get_name(SSL_get_current_cipher(vcert.ssl.get())))
        body += "\n" +  Ssl::CertValidationMsg::param_cipher + "=" + cipherName;

    if (extras)
        body += "\n" +  Ssl::CertValidationMsg::param_extras + "=" + *extras;

    STACK_OF(X509) *peerCerts = PeerValidationCertificatesChain(vcert.ssl);
    if (peerCerts) {
        Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));
        for (int i = 0; i < sk_X509_num(peerCerts); ++i) {
            X509 *cert = sk_X509_value(peerCerts, i);
            PEM_write_bio_X509(bio.get(), cert);
            body = body + "\n" + param_cert + xitoa(i) + "=";
            char *ptr;
            long len = BIO_get_mem_data(bio.get(), &ptr);
            body.append(ptr, (ptr[len-1] == '\n' ? len - 1 : len));
            if (!BIO_reset(bio.get())) {
                // print an error?
            }
        }
    }

    if (vcert.errors) {
        int i = 0;
        for (const Security::CertErrors *err = vcert.errors; err; err = err->next, ++i) {
            body +="\n";
            body = body + param_error_name + xitoa(i) + "=" + GetErrorName(err->element.code) + "\n";
            int errorCertPos = -1;
            if (err->element.cert.get())
                errorCertPos = sk_X509_find(peerCerts, err->element.cert.get());
            if (errorCertPos < 0) {
                // assert this error ?
                debugs(83, 4, "WARNING: wrong cert in cert validator request");
            }
            body += param_error_cert + xitoa(i) + "=";
            body += param_cert + xitoa((errorCertPos >= 0 ? errorCertPos : 0));
        }
    }
}

static int
get_error_id(const char *label, size_t len)
{
    const char *e = label + len -1;
    while (e != label && xisdigit(*e)) --e;
    if (e != label) ++e;
    return strtol(e, 0, 10);
}

/// TODO: Finish conversion to exception-based error handling.
bool
Ssl::CertValidationMsg::tryParsingResponse(CertValidationResponse &resp, std::string &error)
{
    std::vector<CertItem> certs;

    const STACK_OF(X509) *peerCerts = PeerValidationCertificatesChain(resp.ssl);

    const char *param = body.c_str();
    while (*param) {
        while (xisspace(*param)) param++;
        if (! *param)
            break;

        size_t param_len = strcspn(param, "=\r\n");
        if (param[param_len] !=  '=') {
            debugs(83, DBG_IMPORTANT, "WARNING: cert validator response parse error: " << param);
            return false;
        }
        const char *value=param+param_len+1;

        if (param_len > param_cert.length() &&
                strncmp(param, param_cert.c_str(), param_cert.length()) == 0) {
            CertItem ci;
            ci.name.assign(param, param_len);
            Security::CertPointer x509;
            readCertFromMemory(x509, value);
            ci.setCert(x509.get());
            certs.push_back(ci);

            const char *b = strstr(value, "-----END CERTIFICATE-----");
            if (b == NULL) {
                debugs(83, DBG_IMPORTANT, "WARNING: cert Validator response parse error: Failed  to find certificate boundary " << value);
                return false;
            }
            b += strlen("-----END CERTIFICATE-----");
            param = b + 1;
            continue;
        }

        size_t value_len = strcspn(value, "\r\n");
        std::string v(value, value_len);

        debugs(83, 5, "Returned value: " << std::string(param, param_len).c_str() << ": " <<
               v.c_str());

        if (param_len == param_transactionNotes.length() &&
            strncmp(param, param_transactionNotes.c_str(), param_transactionNotes.length()) == 0) {
            resp.notes.importFromHelper(SBuf(v.c_str(), v.length()));
            param = value + value_len;
            continue;
        }

        if (param_len == param_clientNotes.length() &&
            strncmp(param, param_clientNotes.c_str(), param_clientNotes.length()) == 0) {

            // TODO: Support arbitrary client annotations when up-porting.
            static std::string supportedName = "clt_conn_tag=";
            if (v.compare(0, supportedName.size(), supportedName) != 0) {
                throw TextException(ToSBuf("Only annotations named ", supportedName,
                    " can be used for client connection annotation in this Squid version. ",
                    "Found: ", v), Here());
            }
            if (v.find(' ') != std::string::npos) {
                throw TextException(ToSBuf("Only one client connection annotation can be used in this Squid version. ",
                    "Found: ", v), Here());
            }
            resp.notes.importFromHelper(SBuf(v.c_str(), v.length()));

            param = value + value_len;
            continue;
        }

        int errorId = get_error_id(param, param_len);
        Ssl::CertValidationResponse::RecvdError &currentItem = resp.getError(errorId);

        if (param_len > param_error_name.length() &&
                strncmp(param, param_error_name.c_str(), param_error_name.length()) == 0) {
            currentItem.error_no = Ssl::GetErrorCode(v.c_str());
            if (currentItem.error_no == SSL_ERROR_NONE) {
                debugs(83, DBG_IMPORTANT, "WARNING: cert validator response parse error: Unknown SSL Error: " << v);
                return false;
            }
        } else if (param_len > param_error_reason.length() &&
                   strncmp(param, param_error_reason.c_str(), param_error_reason.length()) == 0) {
            currentItem.error_reason = v;
        } else if (param_len > param_error_cert.length() &&
                   strncmp(param, param_error_cert.c_str(), param_error_cert.length()) == 0) {

            if (X509 *cert = getCertByName(certs, v)) {
                debugs(83, 6, "The certificate with id \"" << v << "\" found.");
                currentItem.setCert(cert);
            } else {
                //In this case we assume that the certID is one of the certificates sent
                // to cert validator. The certificates sent to cert validator have names in
                // form "cert_xx" where the "xx" is an integer represents the position of
                // the certificate inside peer certificates list.
                const int certId = get_error_id(v.c_str(), v.length());
                debugs(83, 6, "Cert index in peer certificates list:" << certId);
                //if certId is not correct sk_X509_value returns NULL
                currentItem.setCert(sk_X509_value(peerCerts, certId));
            }
        } else if (param_len > param_error_depth.length() &&
                   strncmp(param, param_error_depth.c_str(), param_error_depth.length()) == 0 &&
                   std::all_of(v.begin(), v.end(), isdigit)) {
            currentItem.error_depth = atoi(v.c_str());
        } else {
            debugs(83, DBG_IMPORTANT, "WARNING: cert validator response parse error: Unknown parameter name " << std::string(param, param_len).c_str());
            return false;
        }

        param = value + value_len;
    }

    /*Run through parsed errors to check for errors*/
    typedef Ssl::CertValidationResponse::RecvdErrors::const_iterator SVCRECI;
    for (SVCRECI i = resp.errors.begin(); i != resp.errors.end(); ++i) {
        if (i->error_no == SSL_ERROR_NONE) {
            debugs(83, DBG_IMPORTANT, "WARNING: cert validator incomplete response: Missing error name from error_id: " << i->id);
            return false;
        }
    }

    return true;
}

bool
Ssl::CertValidationMsg::parseResponse(CertValidationResponse &resp, std::string &error)
{
    try {
        return tryParsingResponse(resp, error);
    } catch (...) {
        debugs(83, DBG_IMPORTANT, "ERROR: cannot parse sslcrtvalidator_program response: " << CurrentException);
        return false;
    }
}

X509 *
Ssl::CertValidationMsg::getCertByName(std::vector<CertItem> const &certs, std::string const & name)
{
    typedef std::vector<CertItem>::const_iterator SVCI;
    for (SVCI ci = certs.begin(); ci != certs.end(); ++ci) {
        if (ci->name.compare(name) == 0)
            return ci->cert.get();
    }
    return NULL;
}

Ssl::CertValidationResponse::RecvdError &
Ssl::CertValidationResponse::getError(int errorId)
{
    typedef Ssl::CertValidationResponse::RecvdErrors::iterator SVCREI;
    for (SVCREI i = errors.begin(); i != errors.end(); ++i) {
        if (i->id == errorId)
            return *i;
    }
    Ssl::CertValidationResponse::RecvdError errItem;
    errItem.id = errorId;
    errors.push_back(errItem);
    return errors.back();
}

void
Ssl::CertValidationResponse::RecvdError::setCert(X509 *aCert)
{
    cert.resetAndLock(aCert);
}

void
Ssl::CertValidationMsg::CertItem::setCert(X509 *aCert)
{
    cert.resetAndLock(aCert);
}

const std::string Ssl::CertValidationMsg::code_cert_validate("cert_validate");
const std::string Ssl::CertValidationMsg::param_domain("domain");
const std::string Ssl::CertValidationMsg::param_cert("cert_");
const std::string Ssl::CertValidationMsg::param_error_name("error_name_");
const std::string Ssl::CertValidationMsg::param_error_reason("error_reason_");
const std::string Ssl::CertValidationMsg::param_error_cert("error_cert_");
const std::string Ssl::CertValidationMsg::param_error_depth("error_depth_");
const std::string Ssl::CertValidationMsg::param_proto_version("proto_version");
const std::string Ssl::CertValidationMsg::param_cipher("cipher");
const std::string Ssl::CertValidationMsg::param_extras("extras");
const std::string Ssl::CertValidationMsg::param_transactionNotes("transaction_notes");
const std::string Ssl::CertValidationMsg::param_clientNotes("client_notes");

