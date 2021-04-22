#include "squid.h"
#include "openssl.h"
#include <vector>

#if !defined(SSL_set_max_proto_version)
static std::vector<std::pair<int, unsigned long>> VersionsOptionsMap = {
#if defined(SSL_OP_NO_SSLv2)
    { SSL2_VERSION, SSL_OP_NO_SSLv2 },
#endif
#if defined(SSL_OP_NO_SSLv3)
    { SSL3_VERSION, SSL_OP_NO_SSLv3 },
#endif
#if defined(SSL_OP_NO_TLSv1)
    { TLS1_VERSION, SSL_OP_NO_TLSv1 },
#endif
#if defined(SSL_OP_NO_TLSv1_1)
    { TLS1_1_VERSION, SSL_OP_NO_TLSv1_1},
#endif
#if defined(SSL_OP_NO_TLSv1_2)
    { TLS1_2_VERSION, SSL_OP_NO_TLSv1_2 },
#endif
#if defined(SSL_OP_NO_TLSv1_3)
    { TLS1_3_VERSION, SSL_OP_NO_TLSv1_3 },
#endif
};

extern "C" int SSL_set_max_proto_version(SSL *ssl, int version)
{
    unsigned long options = 0;
    for (auto it = VersionsOptionsMap.rbegin(); it != VersionsOptionsMap.rend(); ++it) {
        if (it->first == version)
            break;
        options |= it->second;
    }
    SSL_set_options(ssl, options);
    return 1;
}

extern "C" int SSL_set_min_proto_version(SSL *ssl, int version)
{
    long options = 0;
    for (auto it : VersionsOptionsMap) {
        if (it.first == version)
            break;
        options |= it.second;
    }
    SSL_set_options(ssl, options);
    return 1;
}

#endif
