/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HELPER_REPLY_H
#define SQUID_SRC_HELPER_REPLY_H

#include "base/CbcPointer.h"
#include "helper/forward.h"
#include "helper/ReservationId.h"
#include "helper/ResultCode.h"
#include "MemBuf.h"
#include "Notes.h"

#include <ostream>

namespace Helper
{

/**
 * This object stores the reply message from a helper lookup
 * It provides parser routing to accept a raw buffer and process the
 * helper reply into fields for easy access by callers
 */
class Reply
{
private:
    // copy are prohibited for now
    Reply(const Helper::Reply &r);
    Reply &operator =(const Helper::Reply &r);

public:
    explicit Reply(Helper::ResultCode res) : result(res), notes() {}

    /// Creates a NULL reply
    Reply();

    const MemBuf &other() const {return other_.isNull() ? emptyBuf() : other_;};

    /** parse a helper response line format:
     *   line     := [ result ] *#( kv-pair )
     *   kv-pair := OWS token '=' ( quoted-string | token )
     *
     * token are URL-decoded.
     * quoted-string are \-escape decoded and the quotes are stripped.
     */
    // XXX: buf should be const but we may need strwordtok() and rfc1738_unescape()
    //void parse(char *buf, size_t len);
    void finalize();

    bool accumulate(const char *buf, size_t len);

public:
    /// The helper response 'result' field.
    Helper::ResultCode result;

    // list of key=value pairs the helper produced
    NotePairs notes;

    /// The stateful replies should include the reservation ID
    Helper::ReservationId reservationId;
private:
    static void CheckReceivedKey(const SBuf &, const SBuf &);

    void parseResponseKeys();

    /// Return an empty MemBuf.
    const MemBuf &emptyBuf() const;

    /// the remainder of the line
    MemBuf other_;
};

std::ostream &operator <<(std::ostream &, const Reply &);

} // namespace Helper

#endif /* SQUID_SRC_HELPER_REPLY_H */

