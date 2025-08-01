/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

#include "squid.h"

#if USE_SELECT

#include "anyp/PortCfg.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "compat/select.h"
#include "fde.h"
#include "globals.h"
#include "ICP.h"
#include "mgr/Registration.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"

#include <cerrno>
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

static int MAX_POLL_TIME = 1000;    /* see also Comm::QuickPollRequired() */

#ifndef        howmany
#define howmany(x, y)   (((x)+((y)-1))/(y))
#endif
#ifndef        NBBY
#define        NBBY    8
#endif
#define FD_MASK_BYTES sizeof(fd_mask)
#define FD_MASK_BITS (FD_MASK_BYTES*NBBY)

/* STATIC */
static int examine_select(fd_set *, fd_set *);
static int fdIsTcpListener(int fd);
static int fdIsUdpListener(int fd);
static int fdIsDns(int fd);
static OBJH commIncomingStats;
static int comm_check_incoming_select_handlers(int nfds, int *fds);
static void comm_select_dns_incoming(void);
static void commUpdateReadBits(int fd, PF * handler);
static void commUpdateWriteBits(int fd, PF * handler);

static struct timeval zero_tv;
static fd_set global_readfds;
static fd_set global_writefds;
static int nreadfds;
static int nwritefds;

void
Comm::SetSelect(int fd, unsigned int type, PF * handler, void *client_data, time_t timeout)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    assert(F->flags.open || (!handler && !client_data && !timeout));
    debugs(5, 5, "FD " << fd << ", type=" << type <<
           ", handler=" << handler << ", client_data=" << client_data <<
           ", timeout=" << timeout);

    if (type & COMM_SELECT_READ) {
        F->read_handler = handler;
        F->read_data = client_data;
        commUpdateReadBits(fd, handler);
    }

    if (type & COMM_SELECT_WRITE) {
        F->write_handler = handler;
        F->write_data = client_data;
        commUpdateWriteBits(fd, handler);
    }

    if (timeout)
        F->timeout = squid_curtime + timeout;
}

static int
fdIsUdpListener(int fd)
{
    if (icpIncomingConn != nullptr && fd == icpIncomingConn->fd)
        return 1;

    if (icpOutgoingConn != nullptr && fd == icpOutgoingConn->fd)
        return 1;

    return 0;
}

static int
fdIsDns(int fd)
{
    if (fd == DnsSocketA)
        return 1;

    if (fd == DnsSocketB)
        return 1;

    return 0;
}

static int
fdIsTcpListener(int fd)
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (s->listenConn != nullptr && s->listenConn->fd == fd)
            return 1;
    }

    return 0;
}

static int
comm_check_incoming_select_handlers(int nfds, int *fds)
{
    int i;
    int fd;
    int maxfd = 0;
    PF *hdl = nullptr;
    fd_set read_mask;
    fd_set write_mask;
    FD_ZERO(&read_mask);
    FD_ZERO(&write_mask);
    incoming_sockets_accepted = 0;

    for (i = 0; i < nfds; ++i) {
        fd = fds[i];

        if (fd_table[fd].read_handler) {
            FD_SET(fd, &read_mask);

            if (fd > maxfd)
                maxfd = fd;
        }

        if (fd_table[fd].write_handler) {
            FD_SET(fd, &write_mask);

            if (fd > maxfd)
                maxfd = fd;
        }
    }

    if (maxfd++ == 0)
        return -1;

    getCurrentTime();

    ++ statCounter.syscalls.selects;

    if (xselect(maxfd, &read_mask, &write_mask, nullptr, &zero_tv) < 1)
        return incoming_sockets_accepted;

    for (i = 0; i < nfds; ++i) {
        fd = fds[i];

        if (FD_ISSET(fd, &read_mask)) {
            if ((hdl = fd_table[fd].read_handler) != nullptr) {
                fd_table[fd].read_handler = nullptr;
                commUpdateReadBits(fd, nullptr);
                hdl(fd, fd_table[fd].read_data);
            } else {
                debugs(5, DBG_IMPORTANT, "comm_select_incoming: FD " << fd << " NULL read handler");
            }
        }

        if (FD_ISSET(fd, &write_mask)) {
            if ((hdl = fd_table[fd].write_handler) != nullptr) {
                fd_table[fd].write_handler = nullptr;
                commUpdateWriteBits(fd, nullptr);
                hdl(fd, fd_table[fd].write_data);
            } else {
                debugs(5, DBG_IMPORTANT, "comm_select_incoming: FD " << fd << " NULL write handler");
            }
        }
    }

    return incoming_sockets_accepted;
}

static void
comm_select_udp_incoming(void)
{
    int nfds = 0;
    int fds[2];

    if (Comm::IsConnOpen(icpIncomingConn)) {
        fds[nfds] = icpIncomingConn->fd;
        ++nfds;
    }

    if (Comm::IsConnOpen(icpOutgoingConn) && icpIncomingConn != icpOutgoingConn) {
        fds[nfds] = icpOutgoingConn->fd;
        ++nfds;
    }

    if (statCounter.comm_udp.startPolling(nfds)) {
        auto n = comm_check_incoming_select_handlers(nfds, fds);
        statCounter.comm_udp.finishPolling(n, Config.comm_incoming.udp);
    }
}

static void
comm_select_tcp_incoming(void)
{
    int nfds = 0;
    int fds[MAXTCPLISTENPORTS];

    // XXX: only poll sockets that won't be deferred. But how do we identify them?

    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (Comm::IsConnOpen(s->listenConn)) {
            fds[nfds] = s->listenConn->fd;
            ++nfds;
        }
    }

    if (statCounter.comm_tcp.startPolling(nfds)) {
        auto n = comm_check_incoming_select_handlers(nfds, fds);
        statCounter.comm_tcp.finishPolling(n, Config.comm_incoming.tcp);
    }
}

/* Select on all sockets; call handlers for those that are ready. */
Comm::Flag
Comm::DoSelect(int msec)
{
    fd_set readfds;
    fd_set pendingfds;
    fd_set writefds;

    PF *hdl = nullptr;
    int fd;
    int maxfd;
    int num;
    int pending;
    int calldns = 0, calludp = 0, calltcp = 0;
    int maxindex;
    unsigned int k;
    int j;
    fd_mask *fdsp;
    fd_mask *pfdsp;
    fd_mask tmask;

    struct timeval poll_time;
    double timeout = current_dtime + (msec / 1000.0);
    fde *F;

    do {
        double start;
        getCurrentTime();
        start = current_dtime;

        if (statCounter.comm_udp.check())
            comm_select_udp_incoming();

        if (statCounter.comm_dns.check())
            comm_select_dns_incoming();

        if (statCounter.comm_tcp.check())
            comm_select_tcp_incoming();

        calldns = calludp = calltcp = 0;

        maxfd = Biggest_FD + 1;

        memcpy(&readfds, &global_readfds,
               howmany(maxfd, FD_MASK_BITS) * FD_MASK_BYTES);

        memcpy(&writefds, &global_writefds,
               howmany(maxfd, FD_MASK_BITS) * FD_MASK_BYTES);

        /* remove stalled FDs, and deal with pending descriptors */
        pending = 0;

        FD_ZERO(&pendingfds);

        maxindex = howmany(maxfd, FD_MASK_BITS);

        fdsp = (fd_mask *) & readfds;

        for (j = 0; j < maxindex; ++j) {
            if ((tmask = fdsp[j]) == 0)
                continue;   /* no bits here */

            for (k = 0; k < FD_MASK_BITS; ++k) {
                if (!EBIT_TEST(tmask, k))
                    continue;

                /* Found a set bit */
                fd = (j * FD_MASK_BITS) + k;

                if (FD_ISSET(fd, &readfds) && fd_table[fd].flags.read_pending) {
                    FD_SET(fd, &pendingfds);
                    ++pending;
                }
            }
        }

        if (nreadfds + nwritefds == 0) {
            assert(shutting_down);
            return Comm::SHUTDOWN;
        }

        if (msec > MAX_POLL_TIME)
            msec = MAX_POLL_TIME;

        if (pending)
            msec = 0;

        for (;;) {
            poll_time.tv_sec = msec / 1000;
            poll_time.tv_usec = (msec % 1000) * 1000;
            ++ statCounter.syscalls.selects;
            num = xselect(maxfd, &readfds, &writefds, nullptr, &poll_time);
            int xerrno = errno;
            ++ statCounter.select_loops;

            if (num >= 0 || pending > 0)
                break;

            if (ignoreErrno(xerrno))
                break;

            debugs(5, DBG_CRITICAL, MYNAME << "select failure: " << xstrerr(xerrno));

            examine_select(&readfds, &writefds);

            return Comm::COMM_ERROR;

            /* NOTREACHED */
        }

        if (num < 0 && !pending)
            continue;

        getCurrentTime();

        debugs(5, num ? 5 : 8, "comm_select: " << num << "+" << pending << " FDs ready");

        statCounter.select_fds_hist.count(num);

        if (num == 0 && pending == 0)
            continue;

        /* Scan return fd masks for ready descriptors */
        fdsp = (fd_mask *) & readfds;

        pfdsp = (fd_mask *) & pendingfds;

        maxindex = howmany(maxfd, FD_MASK_BITS);

        for (j = 0; j < maxindex; ++j) {
            if ((tmask = (fdsp[j] | pfdsp[j])) == 0)
                continue;   /* no bits here */

            for (k = 0; k < FD_MASK_BITS; ++k) {
                if (tmask == 0)
                    break;  /* no more bits left */

                if (!EBIT_TEST(tmask, k))
                    continue;

                /* Found a set bit */
                fd = (j * FD_MASK_BITS) + k;

                EBIT_CLR(tmask, k); /* this will be done */

                if (fdIsUdpListener(fd)) {
                    calludp = 1;
                    continue;
                }

                if (fdIsDns(fd)) {
                    calldns = 1;
                    continue;
                }

                if (fdIsTcpListener(fd)) {
                    calltcp = 1;
                    continue;
                }

                F = &fd_table[fd];
                debugs(5, 6, "comm_select: FD " << fd << " ready for reading");

                if (nullptr == (hdl = F->read_handler))
                    (void) 0;
                else {
                    F->read_handler = nullptr;
                    commUpdateReadBits(fd, nullptr);
                    hdl(fd, F->read_data);
                    ++ statCounter.select_fds;

                    if (statCounter.comm_udp.check())
                        comm_select_udp_incoming();

                    if (statCounter.comm_dns.check())
                        comm_select_dns_incoming();

                    if (statCounter.comm_tcp.check())
                        comm_select_tcp_incoming();
                }
            }
        }

        fdsp = (fd_mask *) & writefds;

        for (j = 0; j < maxindex; ++j) {
            if ((tmask = fdsp[j]) == 0)
                continue;   /* no bits here */

            for (k = 0; k < FD_MASK_BITS; ++k) {
                if (tmask == 0)
                    break;  /* no more bits left */

                if (!EBIT_TEST(tmask, k))
                    continue;

                /* Found a set bit */
                fd = (j * FD_MASK_BITS) + k;

                EBIT_CLR(tmask, k); /* this will be done */

                if (fdIsUdpListener(fd)) {
                    calludp = 1;
                    continue;
                }

                if (fdIsDns(fd)) {
                    calldns = 1;
                    continue;
                }

                if (fdIsTcpListener(fd)) {
                    calltcp = 1;
                    continue;
                }

                F = &fd_table[fd];
                debugs(5, 6, "comm_select: FD " << fd << " ready for writing");

                if ((hdl = F->write_handler)) {
                    F->write_handler = nullptr;
                    commUpdateWriteBits(fd, nullptr);
                    hdl(fd, F->write_data);
                    ++ statCounter.select_fds;

                    if (statCounter.comm_udp.check())
                        comm_select_udp_incoming();

                    if (statCounter.comm_dns.check())
                        comm_select_dns_incoming();

                    if (statCounter.comm_tcp.check())
                        comm_select_tcp_incoming();
                }
            }
        }

        if (calludp)
            comm_select_udp_incoming();

        if (calldns)
            comm_select_dns_incoming();

        if (calltcp)
            comm_select_tcp_incoming();

        getCurrentTime();

        statCounter.select_time += (current_dtime - start);

        return Comm::OK;
    } while (timeout > current_dtime);
    debugs(5, 8, "comm_select: time out: " << squid_curtime);

    return Comm::TIMEOUT;
}

static void
comm_select_dns_incoming(void)
{
    int nfds = 0;
    int fds[3];

    if (DnsSocketA >= 0) {
        fds[nfds] = DnsSocketA;
        ++nfds;
    }

    if (DnsSocketB >= 0) {
        fds[nfds] = DnsSocketB;
        ++nfds;
    }

    if (statCounter.comm_dns.startPolling(nfds)) {
        auto n = comm_check_incoming_select_handlers(nfds, fds);
        statCounter.comm_dns.finishPolling(n, Config.comm_incoming.dns);
    }
}

void
Comm::SelectLoopInit(void)
{
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
    FD_ZERO(&global_readfds);
    FD_ZERO(&global_writefds);
    nreadfds = nwritefds = 0;

    Mgr::RegisterAction("comm_select_incoming",
                        "comm_incoming() stats",
                        commIncomingStats, 0, 1);
}

/*
 * examine_select - debug routine.
 *
 * I spend the day chasing this core dump that occurs when both the client
 * and the server side of a cache fetch simultaneoulsy abort the
 * connection.  While I haven't really studied the code to figure out how
 * it happens, the snippet below may prevent the cache from exitting:
 *
 * Call this from where the select loop fails.
 */
static int
examine_select(fd_set * readfds, fd_set * writefds)
{
    int fd = 0;
    fd_set read_x;
    fd_set write_x;

    struct timeval tv;
    AsyncCall::Pointer ch = nullptr;
    fde *F = nullptr;

    struct stat sb;
    debugs(5, DBG_CRITICAL, "examine_select: Examining open file descriptors...");

    for (fd = 0; fd < Squid_MaxFD; ++fd) {
        FD_ZERO(&read_x);
        FD_ZERO(&write_x);
        tv.tv_sec = tv.tv_usec = 0;

        if (FD_ISSET(fd, readfds))
            FD_SET(fd, &read_x);
        else if (FD_ISSET(fd, writefds))
            FD_SET(fd, &write_x);
        else
            continue;

        ++ statCounter.syscalls.selects;
        errno = 0;

        if (!fstat(fd, &sb)) {
            debugs(5, 5, "FD " << fd << " is valid.");
            continue;
        }
        int xerrno = errno;

        F = &fd_table[fd];
        debugs(5, DBG_CRITICAL, "fstat(FD " << fd << "): " << xstrerr(xerrno));
        debugs(5, DBG_CRITICAL, "WARNING: FD " << fd << " has handlers, but it's invalid.");
        debugs(5, DBG_CRITICAL, "FD " << fd << " is a " << fdTypeStr[F->type] << " called '" << F->desc << "'");
        debugs(5, DBG_CRITICAL, "tmout:" << F->timeoutHandler << " read:" << F->read_handler << " write:" << F->write_handler);

        for (ch = F->closeHandler; ch != nullptr; ch = ch->Next())
            debugs(5, DBG_CRITICAL, " close handler: " << ch);

        if (F->closeHandler != nullptr) {
            commCallCloseHandlers(fd);
        } else if (F->timeoutHandler != nullptr) {
            debugs(5, DBG_CRITICAL, "examine_select: Calling Timeout Handler");
            ScheduleCallHere(F->timeoutHandler);
        }

        F->closeHandler = nullptr;
        F->timeoutHandler = nullptr;
        F->read_handler = nullptr;
        F->write_handler = nullptr;
        FD_CLR(fd, readfds);
        FD_CLR(fd, writefds);
    }

    return 0;
}

static void
commIncomingStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Current incoming_udp_interval: %d\n",
                      statCounter.comm_udp.interval >> Comm::Incoming::Factor);
    storeAppendPrintf(sentry, "Current incoming_dns_interval: %d\n",
                      statCounter.comm_dns.interval >> Comm::Incoming::Factor);
    storeAppendPrintf(sentry, "Current incoming_tcp_interval: %d\n",
                      statCounter.comm_tcp.interval >> Comm::Incoming::Factor);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Histogram of events per incoming socket type\n");
    storeAppendPrintf(sentry, "ICP Messages handled per comm_select_udp_incoming() call:\n");
    statCounter.comm_udp.history.dump(sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "DNS Messages handled per comm_select_dns_incoming() call:\n");
    statCounter.comm_dns.history.dump(sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "HTTP Messages handled per comm_select_tcp_incoming() call:\n");
    statCounter.comm_tcp.history.dump(sentry, statHistIntDumper);
}

void
commUpdateReadBits(int fd, PF * handler)
{
    if (handler && !FD_ISSET(fd, &global_readfds)) {
        FD_SET(fd, &global_readfds);
        ++nreadfds;
    } else if (!handler && FD_ISSET(fd, &global_readfds)) {
        FD_CLR(fd, &global_readfds);
        --nreadfds;
    }
}

void
commUpdateWriteBits(int fd, PF * handler)
{
    if (handler && !FD_ISSET(fd, &global_writefds)) {
        FD_SET(fd, &global_writefds);
        ++nwritefds;
    } else if (!handler && FD_ISSET(fd, &global_writefds)) {
        FD_CLR(fd, &global_writefds);
        --nwritefds;
    }
}

/* Called by async-io or diskd to speed up the polling */
void
Comm::QuickPollRequired(void)
{
    MAX_POLL_TIME = 10;
}

#endif /* USE_SELECT */

