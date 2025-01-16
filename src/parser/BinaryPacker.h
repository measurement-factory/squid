/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PARSER_BINARYPACKER_H
#define SQUID_SRC_PARSER_BINARYPACKER_H

#include "ip/forward.h"
#include "parser/forward.h"
#include "sbuf/SBuf.h"

/// Serializes various common types using network byte order (where applicable).
/// \sa Parser::BinaryTokenizer that parses serialized fields.
class BinaryPacker
{
public:
    /// packs a single-byte unsigned integer
    void uint8(const char *description, uint8_t);

    /// packs a two-byte unsigned integer
    void uint16(const char *description, uint16_t);

    /// packs all given bytes as an opaque blob
    void area(const char *description, const SBuf &);

    /// packs in_addr or in6_addr structure; port information is not stored
    void inet(const char *description, const Ip::Address &);

    /*
     * Variable-length arrays (a.k.a. Pascal or prefix strings).
     * pstringN() packs an N-bit length field followed by length bytes
     */
    void pstring8(const char *description, const SBuf &); ///< up to 255 byte-long p-string
    void pstring16(const char *description, const SBuf &); ///< up to 64 KiB-long p-string

    /// Optimization: Returns a packer that, when given to pstringClose16(), may
    /// avoid serialized data copying while emulating pstring16() effects. Do
    /// not call non-const methods of this packer object until pstringClose16()
    /// is called with the packer returned by this method.
    BinaryPacker pstringOpen16(const char *description);

    /// Optimization: Commits serialized bytes accumulating in packer object
    /// returned by the previous pstringOpen16() call. Do not call non-const
    /// methods of this packer object after giving it to pstringClose16().
    void pstringClose16(BinaryPacker &&);

    const SBuf &packed() const { return output_; }

private:
    void packOctet_(uint8_t);
    void packOctets_(const void *, size_t);
    template <typename Value> void packed_(const char *description, const Value &, size_t size);

private:
    /// serialized bytes accumulated so far
    SBuf output_;

    /// pstringOpenX() description (for locked packers) or nil (for others):
    /// Calling `y = x.pstringOpen16()` locks packer `x` while subsequent
    /// `x.pstringClose16(y)` call unlocks packer `x` and locks packer `y`.
    const char *lock_ = nullptr;
};

#endif /* SQUID_SRC_PARSER_BINARYPACKER_H */

