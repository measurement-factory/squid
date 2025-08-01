/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 42    ICMP Pinger program */

#define SQUID_HELPER 1

#include "squid.h"

#if USE_ICMP

#include "compat/socket.h"
#include "compat/unistd.h"
#include "debug/Stream.h"
#include "Icmp4.h"
#include "Icmp6.h"
#include "IcmpPinger.h"

#include <cerrno>

IcmpPinger::IcmpPinger() : Icmp()
{
    // these start invalid. Setup properly in Open()
    socket_from_squid = -1;
    socket_to_squid = -1;
}

IcmpPinger::~IcmpPinger()
{
    Close();
}

#if _SQUID_WINDOWS_
void
Win32SockCleanup(void)
{
    WSACleanup();
    return;
}
#endif

int
IcmpPinger::Open(void)
{
#if _SQUID_WINDOWS_

    WSADATA wsaData;
    WSAPROTOCOL_INFO wpi;
    char buf[sizeof(wpi)];
    int x;

    struct sockaddr_in PS;
    int xerrno;

    WSAStartup(2, &wsaData);
    atexit(Win32SockCleanup);

    getCurrentTime();

    Debug::debugOptions = xstrdup("ALL,1");
    Debug::BanCacheLogUse();

    setmode(0, O_BINARY);
    setmode(1, O_BINARY);
    x = xread(0, buf, sizeof(wpi));

    if (x < (int)sizeof(wpi)) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << " read: FD 0: " << xstrerr(xerrno));
        xwrite(1, "ERR\n", 4);
        return -1;
    }

    memcpy(&wpi, buf, sizeof(wpi));

    xwrite(1, "OK\n", 3);
    x = xread(0, buf, sizeof(PS));

    if (x < (int)sizeof(PS)) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << " read: FD 0: " << xstrerr(xerrno));
        xwrite(1, "ERR\n", 4);
        return -1;
    }

    memcpy(&PS, buf, sizeof(PS));

    icmp_sock = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &wpi, 0, 0);

    if (icmp_sock == -1) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << "WSASocket: " << xstrerr(xerrno));
        xwrite(1, "ERR\n", 4);
        return -1;
    }

    x = xconnect(icmp_sock, (struct sockaddr *) &PS, sizeof(PS));

    if (x != 0) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << "connect: " << xstrerr(xerrno));
        xwrite(1, "ERR\n", 4);
        return -1;
    }

    xwrite(1, "OK\n", 3);
    memset(buf, 0, sizeof(buf));
    x = xrecv(icmp_sock, buf, sizeof(buf), 0);

    if (x < 3) {
        xerrno = errno;
        debugs(42, DBG_CRITICAL, MYNAME << "recv: " << xstrerr(xerrno));
        return -1;
    }

    x = xsend(icmp_sock, buf, strlen(buf), 0);
    xerrno = errno;

    if (x < 3 || strncmp("OK\n", buf, 3)) {
        debugs(42, DBG_CRITICAL, MYNAME << "recv: " << xstrerr(xerrno));
        return -1;
    }

    getCurrentTime();
    debugs(42, DBG_IMPORTANT, "Squid socket opened");

    /* windows uses a socket stream as a dual-direction channel */
    socket_to_squid = icmp_sock;
    socket_from_squid = icmp_sock;

    return icmp_sock;

#else /* !_SQUID_WINDOWS_ */

    /* non-windows apps use stdin/out pipes as the squid channel(s) */
    socket_from_squid = 0; // use STDIN macro ??
    socket_to_squid = 1; // use STDOUT macro ??
    return socket_to_squid;
#endif
}

void
IcmpPinger::Close(void)
{
#if _SQUID_WINDOWS_

    shutdown(icmp_sock, SD_BOTH);
    xclose(icmp_sock);
    icmp_sock = -1;
#endif

    /* also shutdown the helper engines */
    icmp4.Close();
    icmp6.Close();
}

void
IcmpPinger::Recv(void)
{
    static pingerEchoData pecho;
    int n;
    int guess_size;

    pecho = pingerEchoData();
    n = xrecv(socket_from_squid, &pecho, sizeof(pecho), 0);

    if (n < 0) {
        debugs(42, DBG_IMPORTANT, "Pinger exiting.");
        Close();
        exit(EXIT_FAILURE);
    }

    if (0 == n) {
        /* EOF indicator */
        debugs(42, DBG_CRITICAL, "EOF encountered. Pinger exiting.");
        errno = 0;
        Close();
        exit(EXIT_FAILURE);
    }

    guess_size = n - (sizeof(pingerEchoData) - PINGER_PAYLOAD_SZ);

    if (guess_size != pecho.psize) {
        debugs(42, 2, "size mismatch, guess=" << guess_size << ", psize=" << pecho.psize);
        /* don't process this message, but keep running */
        return;
    }

    /* pass request for ICMPv6 handing */
    if (pecho.to.isIPv6()) {
        debugs(42, 2, " Pass " << pecho.to << " off to ICMPv6 module.");
        icmp6.SendEcho(pecho.to,
                       pecho.opcode,
                       pecho.payload,
                       pecho.psize);
    }

    /* pass the packet for ICMP handling */
    else if (pecho.to.isIPv4()) {
        debugs(42, 2, " Pass " << pecho.to << " off to ICMPv4 module.");
        icmp4.SendEcho(pecho.to,
                       pecho.opcode,
                       pecho.payload,
                       pecho.psize);
    } else {
        debugs(42, DBG_IMPORTANT, "ERROR: IP has unknown Type. " << pecho.to );
    }
}

void
IcmpPinger::SendResult(pingerReplyData &preply, int len)
{
    debugs(42, 2, "return result to squid. len=" << len);

    if (xsend(socket_to_squid, &preply, len, 0) < 0) {
        int xerrno = errno;
        debugs(42, DBG_CRITICAL, "FATAL: send failure: " << xstrerr(xerrno));
        Close();
        exit(EXIT_FAILURE);
    }
}

#endif /* USE_ICMP */

