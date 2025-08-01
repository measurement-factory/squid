/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "base/IoManip.h"
#include "base/PackableStream.h"
#include "base/TextException.h"
#include "cache_cf.h"
#include "comm/Connection.h"
#include "compat/cmsg.h"
#include "compat/socket.h"
#include "ConfigParser.h"
#include "fde.h"
#include "globals.h"
#include "hier_code.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "Parsing.h"
#include "sbuf/Stream.h"
#include "Store.h"

#include <cerrno>
#include <limits>

CBDATA_CLASS_INIT(acl_tos);

acl_tos::~acl_tos()
{
    aclDestroyAclList(&aclList);
    delete next;
}

CBDATA_CLASS_INIT(acl_nfmark);

acl_nfmark::~acl_nfmark()
{
    aclDestroyAclList(&aclList);
    delete next;
}

void
Ip::Qos::getTosFromServer(const Comm::ConnectionPointer &server, fde *clientFde)
{
#if USE_QOS_TOS && _SQUID_LINUX_
    /* Bug 2537: This part of ZPH only applies to patched Linux kernels. */
    tos_t tos = 1;
    int tos_len = sizeof(tos);
    clientFde->tosFromServer = 0;
    if (xsetsockopt(server->fd,SOL_IP,IP_RECVTOS,&tos,tos_len)==0) {
        unsigned char buf[512];
        int len = 512;
        if (xgetsockopt(server->fd,SOL_IP,IP_PKTOPTIONS,buf,(socklen_t*)&len) == 0) {
            /* Parse the PKTOPTIONS structure to locate the TOS data message
             * prepared in the kernel by the ZPH incoming TCP TOS preserving
             * patch.
             */
            unsigned char * pbuf = buf;
            while (pbuf-buf < len) {
                struct cmsghdr *o = (struct cmsghdr*)pbuf;
                if (o->cmsg_len<=0)
                    break;

                if (o->cmsg_level == SOL_IP && o->cmsg_type == IP_TOS) {
                    int *tmp = (int*)SQUID_CMSG_DATA(o);
                    clientFde->tosFromServer = (tos_t)*tmp;
                    break;
                }
                pbuf += CMSG_LEN(o->cmsg_len);
            }
        } else {
            int xerrno = errno;
            debugs(33, DBG_IMPORTANT, "ERROR: QOS: getsockopt(IP_PKTOPTIONS) failure on " << server << " " << xstrerr(xerrno));
        }
    } else {
        int xerrno = errno;
        debugs(33, DBG_IMPORTANT, "ERROR: QOS: setsockopt(IP_RECVTOS) failure on " << server << " " << xstrerr(xerrno));
    }
#else
    (void)server;
    (void)clientFde;
#endif
}

#if USE_LIBNETFILTERCONNTRACK
/**
* Callback function to mark connection once it's been found.
* This function is called by the libnetfilter_conntrack
* libraries, during nfct_query in Ip::Qos::getNfConnmark.
* nfct_callback_register is used to register this function.
* @param nf_conntrack_msg_type Type of conntrack message
* @param nf_conntrack Pointer to the conntrack structure
* @param mark Pointer to nfmark_t mark
*/
static int
getNfmarkCallback(enum nf_conntrack_msg_type, struct nf_conntrack *ct, void *connmark)
{
    auto *mark = static_cast<nfmark_t *>(connmark);
    *mark = nfct_get_attr_u32(ct, ATTR_MARK);
    debugs(17, 3, "mark=0x" << asHex(*mark));
    return NFCT_CB_CONTINUE;
}

/**
* Prepares a conntrack query for specified source and destination.
* This can be used for querying or modifying attributes.
*/
static nf_conntrack *
prepareConntrackQuery(const Ip::Address &src, const Ip::Address &dst)
{
    /* Allocate a new conntrack */
    if (auto ct = nfct_new()) {
        // Prepare data needed to find the connection in the conntrack table.
        // We need the local and remote IP address, and the local and remote
        // port numbers.
        if (Ip::EnableIpv6 && src.isIPv6()) {
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
            struct in6_addr conn_fde_dst_ip6;
            dst.getInAddr(conn_fde_dst_ip6);
            nfct_set_attr(ct, ATTR_ORIG_IPV6_DST, conn_fde_dst_ip6.s6_addr);
            struct in6_addr conn_fde_src_ip6;
            src.getInAddr(conn_fde_src_ip6);
            nfct_set_attr(ct, ATTR_ORIG_IPV6_SRC, conn_fde_src_ip6.s6_addr);
        } else {
            nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
            struct in_addr conn_fde_dst_ip;
            dst.getInAddr(conn_fde_dst_ip);
            nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, conn_fde_dst_ip.s_addr);
            struct in_addr conn_fde_src_ip;
            src.getInAddr(conn_fde_src_ip);
            nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, conn_fde_src_ip.s_addr);
        }

        nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
        nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, htons(dst.port()));
        nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, htons(src.port()));

        return ct;
    }

    return nullptr;
}
#endif

nfmark_t
Ip::Qos::getNfConnmark(const Comm::ConnectionPointer &conn, const Ip::Qos::ConnectionDirection connDir)
{
    nfmark_t mark = 0;
#if USE_LIBNETFILTERCONNTRACK
    const auto src = (connDir == Ip::Qos::dirAccepted) ? conn->remote : conn->local;
    const auto dst = (connDir == Ip::Qos::dirAccepted) ? conn->local : conn->remote;

    if (const auto ct = prepareConntrackQuery(src, dst)) {
        // Open a handle to the conntrack
        if (struct nfct_handle *h = nfct_open(CONNTRACK, 0)) {
            // Register the callback. The callback function will record the mark value.
            nfct_callback_register(h, NFCT_T_ALL, getNfmarkCallback, static_cast<void *>(&mark));
            // Query the conntrack table using the data previously set
            int x = nfct_query(h, NFCT_Q_GET, ct);
            if (x == -1) {
                const int xerrno = errno;
                debugs(17, 2, "QOS: Failed to retrieve connection mark: (" << x << ") " << xstrerr(xerrno)
                       << " (Destination " << dst << ", source " << src << ")" );
            }
            nfct_close(h);
        } else {
            debugs(17, 2, "QOS: Failed to open conntrack handle for netfilter CONNMARK retrieval.");
        }
        nfct_destroy(ct);
    } else {
        debugs(17, 2, "QOS: Failed to allocate new conntrack for netfilter CONNMARK retrieval.");
    }
#else
    (void)conn;
    (void)connDir;
#endif
    return mark;
}

bool
Ip::Qos::setNfConnmark(Comm::ConnectionPointer &conn, const Ip::Qos::ConnectionDirection connDir, const Ip::NfMarkConfig &cm)
{
    bool ret = false;

#if USE_LIBNETFILTERCONNTRACK
    const auto src = (connDir == Ip::Qos::dirAccepted) ? conn->remote : conn->local;
    const auto dst = (connDir == Ip::Qos::dirAccepted) ? conn->local : conn->remote;

    const nfmark_t newMark = cm.applyToMark(conn->nfConnmark);

    // No need to do anything if a CONNMARK has not changed.
    if (newMark == conn->nfConnmark)
        return true;

    if (const auto ct = prepareConntrackQuery(src, dst)) {
        // Open a handle to the conntrack
        if (struct nfct_handle *h = nfct_open(CONNTRACK, 0)) {
            nfct_set_attr_u32(ct, ATTR_MARK, newMark);
            // Update the conntrack table using the new mark. We do not need a callback here.
            const int queryResult = nfct_query(h, NFCT_Q_UPDATE, ct);
            if (queryResult == 0) {
                conn->nfConnmark = newMark;
                ret = true;
            } else {
                const int xerrno = errno;
                debugs(17, 2, "QOS: Failed to modify connection mark: (" << queryResult << ") " << xstrerr(xerrno)
                       << " (Destination " << dst << ", source " << src << ")" );
            }
            nfct_close(h);
        } else {
            debugs(17, 2, "QOS: Failed to open conntrack handle for netfilter CONNMARK modification.");
        }
        nfct_destroy(ct);
    } else {
        debugs(17, 2, "QOS: Failed to allocate new conntrack for netfilter CONNMARK modification.");
    }
#else /* USE_LIBNETFILTERCONNTRACK */
    (void)conn;
    (void)connDir;
    (void)cm;
#endif /* USE_LIBNETFILTERCONNTRACK */
    return ret;
}

int
Ip::Qos::doTosLocalMiss(const Comm::ConnectionPointer &conn, const hier_code hierCode)
{
    tos_t tos = 0;
    if (Ip::Qos::TheConfig.tosSiblingHit && hierCode==SIBLING_HIT) {
        tos = Ip::Qos::TheConfig.tosSiblingHit;
        debugs(33, 2, "QOS: Sibling Peer hit with hier code=" << hierCode << ", TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.tosParentHit && hierCode==PARENT_HIT) {
        tos = Ip::Qos::TheConfig.tosParentHit;
        debugs(33, 2, "QOS: Parent Peer hit with hier code=" << hierCode << ", TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.preserveMissTos) {
        tos = fd_table[conn->fd].tosFromServer & Ip::Qos::TheConfig.preserveMissTosMask;
        tos = (tos & ~Ip::Qos::TheConfig.tosMissMask) | (Ip::Qos::TheConfig.tosMiss & Ip::Qos::TheConfig.tosMissMask);
        debugs(33, 2, "QOS: Preserving TOS on miss, TOS=" << int(tos));
    } else if (Ip::Qos::TheConfig.tosMiss) {
        tos = Ip::Qos::TheConfig.tosMiss & Ip::Qos::TheConfig.tosMissMask;
        debugs(33, 2, "QOS: Cache miss, setting TOS=" << int(tos));
    }
    return setSockTos(conn, tos);
}

int
Ip::Qos::doNfmarkLocalMiss(const Comm::ConnectionPointer &conn, const hier_code hierCode)
{
    nfmark_t mark = 0;
    if (Ip::Qos::TheConfig.markSiblingHit && hierCode==SIBLING_HIT) {
        mark = Ip::Qos::TheConfig.markSiblingHit;
        debugs(33, 2, "QOS: Sibling Peer hit with hier code=" << hierCode << ", Mark=" << mark);
    } else if (Ip::Qos::TheConfig.markParentHit && hierCode==PARENT_HIT) {
        mark = Ip::Qos::TheConfig.markParentHit;
        debugs(33, 2, "QOS: Parent Peer hit with hier code=" << hierCode << ", Mark=" << mark);
    } else if (Ip::Qos::TheConfig.preserveMissMark) {
        mark = fd_table[conn->fd].nfConnmarkFromServer & Ip::Qos::TheConfig.preserveMissMarkMask;
        mark = (mark & ~Ip::Qos::TheConfig.markMissMask) | (Ip::Qos::TheConfig.markMiss & Ip::Qos::TheConfig.markMissMask);
        debugs(33, 2, "QOS: Preserving mark on miss, Mark=" << mark);
    } else if (Ip::Qos::TheConfig.markMiss) {
        mark = Ip::Qos::TheConfig.markMiss & Ip::Qos::TheConfig.markMissMask;
        debugs(33, 2, "QOS: Cache miss, setting Mark=" << mark);
    }
    return setSockNfmark(conn, mark);
}

int
Ip::Qos::doTosLocalHit(const Comm::ConnectionPointer &conn)
{
    debugs(33, 2, "QOS: Setting TOS for local hit, TOS=" << int(Ip::Qos::TheConfig.tosLocalHit));
    return setSockTos(conn, Ip::Qos::TheConfig.tosLocalHit);
}

int
Ip::Qos::doNfmarkLocalHit(const Comm::ConnectionPointer &conn)
{
    debugs(33, 2, "QOS: Setting netfilter mark for local hit, mark=" << Ip::Qos::TheConfig.markLocalHit);
    return setSockNfmark(conn, Ip::Qos::TheConfig.markLocalHit);
}

/* Qos::Config class */

Ip::Qos::Config Ip::Qos::TheConfig;

Ip::Qos::Config::Config() : tosLocalHit(0), tosSiblingHit(0), tosParentHit(0),
    tosMiss(0), tosMissMask(0), preserveMissTos(false),
    preserveMissTosMask(0xFF), markLocalHit(0), markSiblingHit(0),
    markParentHit(0), markMiss(0), markMissMask(0),
    preserveMissMark(false), preserveMissMarkMask(0xFFFFFFFF),
    tosToServer(nullptr), tosToClient(nullptr), nfmarkToServer(nullptr),
    nfmarkToClient(nullptr)
{
}

void
Ip::Qos::Config::parseConfigLine()
{
    /* parse options ... */
    char *token;
    /* These are set as appropriate and then used to check whether the initial loop has been done */
    bool mark = false;
    bool tos = false;
    /* Assume preserve is true. We don't set at initialisation as this affects isHitTosActive().
       We have to do this now, as we may never match the 'tos' parameter below */
#if !USE_QOS_TOS
    throw TextException(ToSBuf("Invalid option 'qos_flows'. QOS features not enabled in this build"), Here());
#endif

    while ( (token = ConfigParser::NextToken()) ) {

        // Work out TOS or mark. Default to TOS for backwards compatibility
        if (!(mark || tos)) {
            if (strncmp(token, "mark",4) == 0) {
#if HAVE_LIBCAP && SO_MARK
                mark = true;
                // Assume preserve is true. We don't set at initialisation as this affects isHitNfmarkActive()
#if USE_LIBNETFILTERCONNTRACK
                preserveMissMark = true;
# else // USE_LIBNETFILTERCONNTRACK
                preserveMissMark = false;
                debugs(3, DBG_IMPORTANT, "WARNING: Squid not compiled with Netfilter conntrack library. "
                       << "Netfilter mark preservation not available.");
#endif // USE_LIBNETFILTERCONNTRACK

#else // HAVE_LIBCAP && SO_MARK
                throw TextException(ToSBuf("Invalid parameter 'mark' in qos_flows option. ",
                                           "Linux Netfilter marking not available on this platform."), Here());
#endif
            } else if (strncmp(token, "tos",3) == 0) {
                preserveMissTos = true;
                tos = true;
            } else {
                preserveMissTos = true;
                tos = true;
            }
        }

        if (strncmp(token, "local-hit=",10) == 0) {

            if (mark) {
                if (!xstrtoui(&token[10], nullptr, &markLocalHit, 0, std::numeric_limits<nfmark_t>::max())) {
                    throw TextException(ToSBuf("Bad mark local-hit value ", &token[10]), Here());
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[10], nullptr, &v, 0, std::numeric_limits<tos_t>::max())) {
                    throw TextException(ToSBuf("Bad TOS local-hit value ", &token[10]), Here());
                }
                tosLocalHit = (tos_t)v;
            }

        } else if (strncmp(token, "sibling-hit=",12) == 0) {

            if (mark) {
                if (!xstrtoui(&token[12], nullptr, &markSiblingHit, 0, std::numeric_limits<nfmark_t>::max())) {
                    throw TextException(ToSBuf("Bad mark sibling-hit value ", &token[12]), Here());
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[12], nullptr, &v, 0, std::numeric_limits<tos_t>::max())) {
                    throw TextException(ToSBuf("Bad TOS sibling-hit value ", &token[12]), Here());
                }
                tosSiblingHit = (tos_t)v;
            }

        } else if (strncmp(token, "parent-hit=",11) == 0) {

            if (mark) {
                if (!xstrtoui(&token[11], nullptr, &markParentHit, 0, std::numeric_limits<nfmark_t>::max())) {
                    throw TextException(ToSBuf("Bad mark parent-hit value ", &token[11]), Here());
                }
            } else {
                unsigned int v = 0;
                if (!xstrtoui(&token[11], nullptr, &v, 0, std::numeric_limits<tos_t>::max())) {
                    throw TextException(ToSBuf("Bad TOS parent-hit value ", &token[11]), Here());
                }
                tosParentHit = (tos_t)v;
            }

        } else if (strncmp(token, "miss=",5) == 0) {

            if (mark) {
                char *end = nullptr;
                if (!xstrtoui(&token[5], &end, &markMiss, 0, std::numeric_limits<nfmark_t>::max())) {
                    throw TextException(ToSBuf("Bad mark miss value ", &token[5]), Here());
                }
                Assure(end);
                if (*end == '/') {
                    if (!xstrtoui(end + 1, nullptr, &markMissMask, 0, std::numeric_limits<nfmark_t>::max())) {
                        debugs(3, DBG_CRITICAL, "ERROR: Bad mark miss mask value " << (end + 1) << ". Using 0xFFFFFFFF instead.");
                        markMissMask = 0xFFFFFFFF;
                    }
                } else {
                    markMissMask = 0xFFFFFFFF;
                }
            } else {
                char *end = nullptr;
                unsigned int v = 0;
                if (!xstrtoui(&token[5], &end, &v, 0, std::numeric_limits<tos_t>::max())) {
                    throw TextException(ToSBuf("Bad TOS miss value ", &token[5]), Here());
                }
                tosMiss = (tos_t)v;
                Assure(end);
                if (*end == '/') {
                    if (!xstrtoui(end + 1, nullptr, &v, 0, std::numeric_limits<tos_t>::max())) {
                        debugs(3, DBG_CRITICAL, "ERROR: Bad TOS miss mask value " << (end + 1) << ". Using 0xFF instead.");
                        tosMissMask = 0xFF;
                    } else
                        tosMissMask = (tos_t)v;
                } else {
                    tosMissMask = 0xFF;
                }
            }

        } else if (strcmp(token, "disable-preserve-miss") == 0) {

            if (preserveMissTosMask!=0xFFU || preserveMissMarkMask!=0xFFFFFFFFU) {
                throw TextException(ToSBuf("miss-mask feature cannot be set with disable-preserve-miss"), Here());
            }
            if (mark) {
                preserveMissMark = false;
                preserveMissMarkMask = 0;
            } else {
                preserveMissTos = false;
                preserveMissTosMask = 0;
            }

        } else if (strncmp(token, "miss-mask=",10) == 0) {

            if (mark && preserveMissMark) {
                if (!xstrtoui(&token[10], nullptr, &preserveMissMarkMask, 0, std::numeric_limits<nfmark_t>::max())) {
                    throw TextException(ToSBuf("Bad mark miss-mark value ", &token[10]), Here());
                }
            } else if (preserveMissTos) {
                unsigned int v = 0;
                if (!xstrtoui(&token[10], nullptr, &v, 0, std::numeric_limits<tos_t>::max())) {
                    throw TextException(ToSBuf("Bad TOS miss-mark value ", &token[10]), Here());
                }
                preserveMissTosMask = (tos_t)v;
            } else {
                throw TextException(ToSBuf("miss-mask feature cannot be set without miss-preservation enabled"), Here());
            }

        }
    }
}

/// helper function for printing Ip::Qos::Config mark and tos values
template <class Integer>
static auto asQosConfigHex(const Integer n) { return asHex(n).upperCase().minDigits(2); }

/// report configuration using qos_flows syntax
void
Ip::Qos::Config::dumpConfigLine(std::ostream &os, const char *directiveName) const
{
    if (isHitTosActive()) {
        os << directiveName << " tos";

        if (tosLocalHit > 0) {
            os << " local-hit=0x" << asQosConfigHex(tosLocalHit);
        }
        if (tosSiblingHit > 0) {
            os << " sibling-hit=0x" << asQosConfigHex(tosSiblingHit);
        }
        if (tosParentHit > 0) {
            os << " parent-hit=0x" << asQosConfigHex(tosParentHit);
        }
        if (tosMiss > 0) {
            os << " miss=0x" << asQosConfigHex(tosMiss);
            if (tosMissMask!=0xFFU) {
                os << "/0x" << asQosConfigHex(tosMissMask);
            }
        }
        if (preserveMissTos == 0) {
            os << " disable-preserve-miss";
        }
        if (preserveMissTos && preserveMissTosMask != 0) {
            os << " miss-mask=0x" << asQosConfigHex(preserveMissTosMask);
        }
        os << "\n";
        return;
    }

    if (isHitNfmarkActive()) {
        os << directiveName << " mark";

        if (markLocalHit > 0) {
            os << " local-hit=0x" << asQosConfigHex(markLocalHit);
        }
        if (markSiblingHit > 0) {
            os << " sibling-hit=0x" << asQosConfigHex(markSiblingHit);
        }
        if (markParentHit > 0) {
            os << " parent-hit=0x" << asQosConfigHex(markParentHit);
        }
        if (markMiss > 0) {
            os << " miss=0x" << asQosConfigHex(markMiss);
            if (markMissMask!=0xFFFFFFFFU) {
                os << "/0x" << asQosConfigHex(markMissMask);
            }
        }
        if (preserveMissMark == false) {
            os << " disable-preserve-miss";
        }
        if (preserveMissMark && preserveMissMarkMask != 0) {
            os << " miss-mask=" << asQosConfigHex(preserveMissMarkMask);
        }
        os << "\n";
    }
}

int
Ip::Qos::setSockTos(const int fd, tos_t tos, int type)
{
    // Bug 3731: FreeBSD produces 'invalid option'
    // unless we pass it a 32-bit variable storing 8-bits of data.
    // NP: it is documented as 'int' for all systems, even those like Linux which accept 8-bit char
    //     so we convert to a int before setting.
    int bTos = tos;

    debugs(50, 3, "for FD " << fd << " to " << bTos);

    if (type == AF_INET) {
#if defined(IP_TOS)
        const int x = xsetsockopt(fd, IPPROTO_IP, IP_TOS, &bTos, sizeof(bTos));
        if (x < 0) {
            int xerrno = errno;
            debugs(50, 2, "setsockopt(IP_TOS) on " << fd << ": " << xstrerr(xerrno));
        }
        return x;
#else
        debugs(50, DBG_IMPORTANT, "WARNING: setsockopt(IP_TOS) not supported on this platform");
        return -1;
#endif
    } else { // type == AF_INET6
#if defined(IPV6_TCLASS)
        const int x = xsetsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &bTos, sizeof(bTos));
        if (x < 0) {
            int xerrno = errno;
            debugs(50, 2, "setsockopt(IPV6_TCLASS) on " << fd << ": " << xstrerr(xerrno));
        }
        return x;
#else
        debugs(50, DBG_IMPORTANT, "WARNING: setsockopt(IPV6_TCLASS) not supported on this platform");
        return -1;
#endif
    }

    /* CANNOT REACH HERE */
}

int
Ip::Qos::setSockTos(const Comm::ConnectionPointer &conn, tos_t tos)
{
    const int x = Ip::Qos::setSockTos(conn->fd, tos, conn->remote.isIPv4() ? AF_INET : AF_INET6);
    conn->tos = (x >= 0) ? tos : 0;
    return x;
}

int
Ip::Qos::setSockNfmark(const int fd, nfmark_t mark)
{
#if HAVE_LIBCAP && SO_MARK
    debugs(50, 3, "for FD " << fd << " to " << mark);
    const int x = xsetsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(nfmark_t));
    if (x < 0) {
        int xerrno = errno;
        debugs(50, 2, "setsockopt(SO_MARK) on " << fd << ": " << xstrerr(xerrno));
    }
    return x;
#elif HAVE_LIBCAP
    (void)mark;
    (void)fd;
    debugs(50, DBG_IMPORTANT, "WARNING: setsockopt(SO_MARK) not supported on this platform");
    return -1;
#else
    (void)mark;
    (void)fd;
    debugs(50, DBG_IMPORTANT, "WARNING: Netfilter marking disabled (requires build --with-cap)");
    return -1;
#endif
}

int
Ip::Qos::setSockNfmark(const Comm::ConnectionPointer &conn, nfmark_t mark)
{
    const int x = Ip::Qos::setSockNfmark(conn->fd, mark);
    conn->nfmark = (x >= 0) ? mark : 0;
    return x;
}

bool
Ip::Qos::Config::isAclNfmarkActive() const
{
    acl_nfmark * nfmarkAcls [] = { nfmarkToServer, nfmarkToClient };

    for (int i=0; i<2; ++i) {
        while (nfmarkAcls[i]) {
            acl_nfmark *l = nfmarkAcls[i];
            if (!l->markConfig.isEmpty())
                return true;
            nfmarkAcls[i] = l->next;
        }
    }

    return false;
}

bool
Ip::Qos::Config::isAclTosActive() const
{
    acl_tos * tosAcls [] = { tosToServer, tosToClient };

    for (int i=0; i<2; ++i) {
        while (tosAcls[i]) {
            acl_tos *l = tosAcls[i];
            if (l->tos > 0)
                return true;
            tosAcls[i] = l->next;
        }
    }

    return false;
}

void
dump_QosConfig(StoreEntry * const entry, const char * const directiveName, const Ip::Qos::Config &config)
{
    PackableStream os(*entry);
    config.dumpConfigLine(os, directiveName);
}
