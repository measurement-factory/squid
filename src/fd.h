/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 51    Filedescriptor Functions */

#ifndef SQUID_FD_H_
#define SQUID_FD_H_

namespace Comm {

/// a cheap unique pointer to an open Comm-registered socket or file descriptor
class Descriptor
{
public:
    /// Starts owning the given FD of a given type, with a given description.
    /// Assumes the given descriptor is open and calls legacy fd_open().
    Descriptor(int fd, unsigned int type, const char *description);
    Descriptor(Descriptor &&) = delete; // no copying (and, for now, moving) of any kind

    /// Closes and calls legacy fd_close() unless release() was called earlier.
    ~Descriptor();

    /// Forgets the descriptor and prevents its automatic closure (by us).
    int release() { const auto result = fd_; fd_ = -1; return result; }

private:
    int fd_;
};

} // namespace Comm

void fd_close(int fd);
void fd_open(int fd, unsigned int type, const char *);
void fd_note(int fd, const char *);
void fd_bytes(int fd, int len, unsigned int type);
void fdDumpOpen(void);
int fdUsageHigh(void);
void fdAdjustReserved(void);
int default_read_method(int, char *, int);
int default_write_method(int, const char *, int);

#endif /* SQUID_FD_H_ */

