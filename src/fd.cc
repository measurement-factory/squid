/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 51    Filedescriptor Functions */

#include "squid.h"
#include "comm/Loops.h"
#include "compat/socket.h"
#include "compat/unistd.h"
#include "debug/Messages.h"
#include "debug/Stream.h"
#include "fatal.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"

int default_read_method(int, char *, int);
int default_write_method(int, const char *, int);
#if _SQUID_WINDOWS_
int socket_read_method(int, char *, int);
int socket_write_method(int, const char *, int);
int file_read_method(int, char *, int);
int file_write_method(int, const char *, int);
#else
int msghdr_read_method(int, char *, int);
int msghdr_write_method(int, const char *, int);
#endif

const char *fdTypeStr[] = {
    "None",
    "Log",
    "File",
    "Socket",
    "Pipe",
    "MsgHdr",
    "Unknown"
};

static void fdUpdateBiggest(int fd, int);

static void
fdUpdateBiggest(int fd, int opening)
{
    if (fd < Biggest_FD)
        return;

    assert(fd < Squid_MaxFD);

    if (fd > Biggest_FD) {
        /*
         * assert that we are not closing a FD bigger than
         * our known biggest FD
         */
        assert(opening);
        Biggest_FD = fd;
        return;
    }

    /* if we are here, then fd == Biggest_FD */
    /*
     * assert that we are closing the biggest FD; we can't be
     * re-opening it
     */
    assert(!opening);

    while (Biggest_FD >= 0 && !fd_table[Biggest_FD].flags.open)
        --Biggest_FD;
}

void
fd_close(int fd)
{
    fde *F = &fd_table[fd];

    assert(fd >= 0);
    assert(F->flags.open);

    if (F->type == FD_FILE) {
        assert(F->read_handler == nullptr);
        assert(F->write_handler == nullptr);
    }

    debugs(51, 3, "fd_close FD " << fd << " " << F->desc);
    Comm::ResetSelect(fd);
    F->flags.open = false;
    fdUpdateBiggest(fd, 0);
    --Number_FD;
    F->clear();
}

#if _SQUID_WINDOWS_

int
socket_read_method(int fd, char *buf, int len)
{
    return xrecv(fd, (void *) buf, len, 0);
}

int
file_read_method(int fd, char *buf, int len)
{
    return _read(fd, buf, len);
}

int
socket_write_method(int fd, const char *buf, int len)
{
    return xsend(fd, buf, len, 0);
}

int
file_write_method(int fd, const char *buf, int len)
{
    return _write(fd, buf, len);
}

#else
int
default_read_method(int fd, char *buf, int len)
{
    return xread(fd, buf, len);
}

int
default_write_method(int fd, const char *buf, int len)
{
    return xwrite(fd, buf, len);
}

int
msghdr_read_method(int fd, char *buf, int)
{
    return recvmsg(fd, reinterpret_cast<msghdr*>(buf), MSG_DONTWAIT);
}

int
msghdr_write_method(int fd, const char *buf, int len)
{
    const int i = sendmsg(fd, reinterpret_cast<const msghdr*>(buf), MSG_NOSIGNAL);
    return i > 0 ? len : i; // len is imprecise but the caller expects a match
}

#endif

void
fd_open(int fd, unsigned int type, const char *desc)
{
    fde *F;
    assert(fd >= 0);
    F = &fd_table[fd];

    if (F->flags.open) {
        debugs(51, DBG_IMPORTANT, "WARNING: Closing open FD " << std::setw(4) << fd);
        fd_close(fd);
    }

    assert(!F->flags.open);
    debugs(51, 3, "fd_open() FD " << fd << " " << desc);
    F->type = type;
    F->flags.open = true;
    F->epoll_state = 0;
#if _SQUID_WINDOWS_

    F->win32.handle = _get_osfhandle(fd);

    switch (type) {

    case FD_SOCKET:

    case FD_PIPE:
        F->setIo(&socket_read_method, &socket_write_method);
        break;

    case FD_FILE:

    case FD_LOG:
        F->setIo(&file_read_method, &file_write_method);
        break;

    default:
        fatalf("fd_open(): unknown FD type - FD#: %i, type: %u, desc %s\n", fd, type, desc);
    }

#else
    switch (type) {

    case FD_MSGHDR:
        F->setIo(&msghdr_read_method, &msghdr_write_method);
        break;

    default:
        F->setIo(&default_read_method, &default_write_method);
        break;
    }

#endif

    fdUpdateBiggest(fd, 1);

    fd_note(fd, desc);

    ++Number_FD;
}

void
fd_note(int fd, const char *s)
{
    fde *F = &fd_table[fd];
    if (s)
        xstrncpy(F->desc, s, FD_DESC_SZ);
    else
        *(F->desc) = 0; // ""-string
}

void
fd_bytes(const int fd, const int len, const IoDirection direction)
{
    fde *F = &fd_table[fd];

    if (len < 0)
        return;

    switch (direction) {
    case IoDirection::Read:
        F->bytes_read += len;
        break;
    case IoDirection::Write:
        F->bytes_written += len;
        break;
    }
}

void
fdDumpOpen(void)
{
    int i;
    fde *F;

    for (i = 0; i < Squid_MaxFD; ++i) {
        F = &fd_table[i];

        if (!F->flags.open)
            continue;

        if (i == fileno(DebugStream()))
            continue;

        debugs(51, Important(17), "Open FD "<< std::left<< std::setw(10) <<
               (F->bytes_read && F->bytes_written ? "READ/WRITE" :
                F->bytes_read ? "READING" : F->bytes_written ? "WRITING" :
                "UNSTARTED")  <<
               " "<< std::right << std::setw(4) << i  << " " << F->desc);
    }
}

int
fdNFree(void)
{
    return Squid_MaxFD - Number_FD - Opening_FD;
}

int
fdUsageHigh(void)
{
    int nrfree = fdNFree();

    if (nrfree < (RESERVED_FD << 1))
        return 1;

    if (nrfree < (Number_FD >> 2))
        return 1;

    return 0;
}

/* Called when we runs out of file descriptors */
void
fdAdjustReserved(void)
{
    int newReserve;
    int x;
    static time_t last = 0;
    /*
     * don't update too frequently
     */

    if (last + 5 > squid_curtime)
        return;

    /*
     * Calculate a new reserve, based on current usage and a small extra
     */
    newReserve = Squid_MaxFD - Number_FD + min(25, Squid_MaxFD / 16);

    if (newReserve <= RESERVED_FD)
        return;

    x = Squid_MaxFD - 20 - min(25, Squid_MaxFD / 16);

    if (newReserve > x) {
        /* perhaps this should be fatal()? -DW */
        debugs(51, DBG_CRITICAL, "WARNING: This machine has a serious shortage of filedescriptors.");
        newReserve = x;
    }

    if (Squid_MaxFD - newReserve < min(256, Squid_MaxFD / 2))
        fatalf("Too few filedescriptors available in the system (%d usable of %d).\n", Squid_MaxFD - newReserve, Squid_MaxFD);

    debugs(51, DBG_CRITICAL, "Reserved FD adjusted from " << RESERVED_FD << " to " << newReserve <<
           " due to failures (" << (Squid_MaxFD - newReserve) << "/" << Squid_MaxFD << " file descriptors available)");
    RESERVED_FD = newReserve;
}

