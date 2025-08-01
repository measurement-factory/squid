/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/File.h"
#include "compat/socket.h"
#include "compat/unistd.h"
#include "debug/Stream.h"
#include "sbuf/Stream.h"
#include "tools.h"

#include <chrono>
#include <thread>
#include <utility>

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* FileOpeningConfig */

FileOpeningConfig
FileOpeningConfig::ReadOnly()
{
    FileOpeningConfig cfg;

    /* I/O */
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    cfg.desiredAccess = GENERIC_READ;
    cfg.shareMode = FILE_SHARE_READ;
#else
    cfg.openFlags = O_RDONLY;
#endif

    /* locking (if enabled later) */
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    cfg.lockFlags = 0; // no named constant for a shared lock
#elif _SQUID_SOLARIS_
    cfg.lockType = F_RDLCK;
#else
    cfg.flockMode = LOCK_SH | LOCK_NB;
#endif

    return cfg;
}

FileOpeningConfig
FileOpeningConfig::ReadWrite()
{
    FileOpeningConfig cfg;

    /* I/O */
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    cfg.desiredAccess = GENERIC_READ | GENERIC_WRITE;
    cfg.shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
#else
    cfg.openFlags = O_RDWR;
#endif

    /* locking (if enabled later) */
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    cfg.lockFlags = LOCKFILE_EXCLUSIVE_LOCK;
#elif _SQUID_SOLARIS_
    cfg.lockType = F_WRLCK;
#else
    cfg.flockMode = LOCK_EX | LOCK_NB;
#endif

    return cfg;
}

FileOpeningConfig &
FileOpeningConfig::locked(unsigned int attempts)
{
    lockAttempts = attempts;
    // for simplicity, correct locking flags are preset in constructing methods
    return *this;
}

FileOpeningConfig &
FileOpeningConfig::createdIfMissing()
{
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    Must((desiredAccess & GENERIC_WRITE) == GENERIC_WRITE);
    creationDisposition = OPEN_ALWAYS;
#else
    Must((openFlags & O_RDWR) == O_RDWR);
    openFlags |= O_CREAT;
    creationMask = (S_IXUSR | S_IXGRP|S_IWGRP | S_IXOTH|S_IWOTH); // unwanted bits
#endif
    return *this;
}

/* File */

#if _SQUID_SOLARIS_
// XXX: fcntl() locks are incompatible with complex applications that may lock
// multiple open descriptors corresponding to the same underlying file. There is
// nothing better on Solaris, but do not be tempted to use this elsewhere. For
// more info, see https://bugs.squid-cache.org/show_bug.cgi?id=4212#c14
/// fcntl(... struct flock) convenience wrapper
static int
fcntlLock(const int fd, const short lockType)
{
    // the exact composition and order of flock data members is unknown!
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = lockType;
    fl.l_whence = SEEK_SET; // with zero l_len and l_start, means "whole file"
    return ::fcntl(fd, F_SETLK, &fl);
}
#endif // _SQUID_SOLARIS_

File *
File::Optional(const SBuf &filename, const FileOpeningConfig &cfg)
{
    try {
        return new File(filename, cfg);
    }
    catch (const std::exception &ex) {
        debugs(54, 5, "will not lock: " << ex.what());
    }
    return nullptr;
}

File::File(const SBuf &aName, const FileOpeningConfig &cfg):
    name_(aName)
{
    debugs(54, 7, "constructing, this=" << this << ' ' << name_);
    // close the file during post-open constructor exceptions
    try {
        open(cfg);
        lock(cfg);
    }
    catch (...)
    {
        close();
        throw;
    }
}

File::~File()
{
    debugs(54, 7, "destructing, this=" << this << ' ' << name_);
    close();
}

File::File(File &&other)
{
    *this = std::move(other);
}

File &
File::operator = (File &&other)
{
    std::swap(fd_, other.fd_);
    return *this;
}

/// opens (or creates) the file
void
File::open(const FileOpeningConfig &cfg)
{
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    fd_ = CreateFile(TEXT(name_.c_str()), cfg.desiredAccess, cfg.shareMode, nullptr, cfg.creationDisposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fd_ == InvalidHandle) {
        const auto savedError = GetLastError();
        throw TexcHere(sysCallFailure("CreateFile", WindowsErrorMessage(savedError)));
    }
#else
    mode_t oldCreationMask = 0;
    const auto filename = name_.c_str(); // avoid complex operations inside enter_suid()
    enter_suid();
    if (cfg.creationMask)
        oldCreationMask = umask(cfg.creationMask); // XXX: Why here? Should not this be set for the whole Squid?
    fd_ = xopen(filename, cfg.openFlags, cfg.openMode);
    const auto savedErrno = errno;
    if (cfg.creationMask)
        umask(oldCreationMask);
    leave_suid();
    if (fd_ < 0)
        throw TexcHere(sysCallError("open", savedErrno));
#endif
}

void
File::close()
{
    if (!isOpen())
        return;
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    if (!CloseHandle(fd_)) {
        const auto savedError = GetLastError();
        debugs(54, DBG_IMPORTANT, sysCallFailure("CloseHandle", WindowsErrorMessage(savedError)));
    }
#else
    if (xclose(fd_) != 0) {
        const auto savedErrno = errno;
        debugs(54, DBG_IMPORTANT, sysCallError("close", savedErrno));
    }
#endif
    // closing the file handler implicitly removes all associated locks
}

void
File::truncate()
{
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    if (!SetFilePointer(fd_, 0, nullptr, FILE_BEGIN)) {
        const auto savedError = GetLastError();
        throw TexcHere(sysCallFailure("SetFilePointer", WindowsErrorMessage(savedError)));
    }

    if (!SetEndOfFile(fd_)) {
        const auto savedError = GetLastError();
        throw TexcHere(sysCallFailure("SetEndOfFile", WindowsErrorMessage(savedError)));
    }
#else
    if (::lseek(fd_, SEEK_SET, 0) < 0) {
        const auto savedErrno = errno;
        throw TexcHere(sysCallError("lseek", savedErrno));
    }

    if (::ftruncate(fd_, 0) != 0) {
        const auto savedErrno = errno;
        throw TexcHere(sysCallError("ftruncate", savedErrno));
    }
#endif
}

SBuf
File::readSmall(const SBuf::size_type minBytes, const SBuf::size_type maxBytes)
{
    SBuf buf;
    const auto readLimit = maxBytes + 1; // to detect excessively large files that we do not handle
    char *rawBuf = buf.rawAppendStart(readLimit);
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    DWORD result = 0;
    if (!ReadFile(fd_, rawBuf, readLimit, &result, nullptr)) {
        const auto savedError = GetLastError();
        throw TexcHere(sysCallFailure("ReadFile", WindowsErrorMessage(savedError)));
    }
#else
    const auto result = xread(fd_, rawBuf, readLimit);
    if (result < 0) {
        const auto savedErrno = errno;
        throw TexcHere(sysCallError("read", savedErrno));
    }
#endif
    const auto bytesRead = static_cast<size_t>(result);
    assert(bytesRead <= readLimit);
    Must(!buf.length());
    buf.rawAppendFinish(rawBuf, bytesRead);

    if (buf.length() < minBytes) {
        static const SBuf errPrematureEof("premature eof");
        static const SBuf errEmptyFile("empty file");
        throw TexcHere(sysCallFailure("read", buf.length() ? errPrematureEof : errEmptyFile));
    }

    if (buf.length() > maxBytes) {
        static const SBuf failure("unreasonably large file");
        throw TexcHere(sysCallFailure("read", failure));
    }

    Must(minBytes <= buf.length() && buf.length() <= maxBytes);
    return buf;
}

void
File::writeAll(const SBuf &data)
{
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    DWORD nBytesWritten = 0;
    if (!WriteFile(fd_, data.rawContent(), data.length(), &nBytesWritten, nullptr)) {
        const auto savedError = GetLastError();
        throw TexcHere(sysCallFailure("WriteFile", WindowsErrorMessage(savedError)));
    }
    const auto bytesWritten = static_cast<size_t>(nBytesWritten);
#else
    const auto result = xwrite(fd_, data.rawContent(), data.length());
    if (result < 0) {
        const auto savedErrno = errno;
        throw TexcHere(sysCallError("write", savedErrno));
    }
    const auto bytesWritten = static_cast<size_t>(result);
#endif
    if (bytesWritten != data.length()) {
        static const SBuf failure("partial write");
        throw TexcHere(sysCallFailure("write", failure));
    }
}

void
File::synchronize()
{
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    if (!FlushFileBuffers(fd_)) {
        const auto savedError = GetLastError();
        throw TexcHere(sysCallFailure("FlushFileBuffers", WindowsErrorMessage(savedError)));
    }
#else
    if (::fsync(fd_) != 0) {
        const auto savedErrno = errno;
        throw TexcHere(sysCallError("fsync", savedErrno));
    }
#endif
}

/// calls lockOnce() as many times as necessary (including zero)
void
File::lock(const FileOpeningConfig &cfg)
{
    unsigned int attemptsLeft = cfg.lockAttempts;
    while (attemptsLeft) {
        try {
            --attemptsLeft;
            return lockOnce(cfg);
        } catch (const std::exception &ex) {
            if (!attemptsLeft)
                throw;
            debugs(54, 4, "sleeping and then trying up to " << attemptsLeft <<
                   " more time(s) after a failure: " << ex.what());
        }
        Must(attemptsLeft); // the catch statement handles the last attempt
        std::this_thread::sleep_for(std::chrono::microseconds(cfg.retryGapUsec));
    }
    debugs(54, 9, "disabled");
}

/// locks, blocking or returning immediately depending on the lock waiting mode
void
File::lockOnce(const FileOpeningConfig &cfg)
{
#if _SQUID_WINDOWS_ || _SQUID_MINGW_
    if (!LockFileEx(fd_, cfg.lockFlags, 0, 0, 1, 0)) {
        const auto savedError = GetLastError();
        throw TexcHere(sysCallFailure("LockFileEx", WindowsErrorMessage(savedError)));
    }
#elif _SQUID_SOLARIS_
    if (fcntlLock(fd_, cfg.lockType) != 0) {
        const auto savedErrno = errno;
        throw TexcHere(sysCallError("fcntl(flock)", savedErrno));
    }
#else
    if (::flock(fd_, cfg.flockMode) != 0) {
        const auto savedErrno = errno;
        throw TexcHere(sysCallError("flock", savedErrno));
    }
#endif
    debugs(54, 3, "succeeded for " << name_);
}

/// \returns a description a system call-related failure
SBuf
File::sysCallFailure(const char *callName, const SBuf &error) const
{
    return ToSBuf("failed to ", callName, ' ', name_, ": ", error);
}

/// \returns a description of an errno-based system call failure
SBuf
File::sysCallError(const char *callName, const int savedErrno) const
{
    return sysCallFailure(callName, SBuf(xstrerr(savedErrno)));
}

#if _SQUID_WINDOWS_ || _SQUID_MINGW_
const HANDLE File::InvalidHandle = INVALID_HANDLE_VALUE;
#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_*/

