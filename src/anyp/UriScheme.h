/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ANYP_URISCHEME_H
#define SQUID_SRC_ANYP_URISCHEME_H

#include "anyp/ProtocolType.h"
#include "sbuf/SBuf.h"

#include <iosfwd>
#include <optional>
#include <vector>

namespace AnyP
{

/// validated/supported port number; these values are never zero
using KnownPort = uint16_t;

/// validated/supported port number (if any)
using Port = std::optional<KnownPort>;

/** This class represents a URI Scheme such as http:// https://, wais://, urn: etc.
 * It does not represent the PROTOCOL that such schemes refer to.
 */
class UriScheme
{
public:
    typedef std::vector<SBuf> LowercaseSchemeNames;

    UriScheme() : theScheme_(AnyP::PROTO_NONE) {}
    /// \param img Explicit scheme representation for unknown/none schemes.
    UriScheme(AnyP::ProtocolType const aScheme, const char *img = nullptr);
    UriScheme(const AnyP::UriScheme &o) : theScheme_(o.theScheme_), image_(o.image_) {}
    UriScheme(AnyP::UriScheme &&) = default;
    ~UriScheme() {}

    AnyP::UriScheme& operator=(const AnyP::UriScheme &o) {
        theScheme_ = o.theScheme_;
        image_ = o.image_;
        return *this;
    }
    AnyP::UriScheme& operator=(AnyP::UriScheme &&) = default;

    operator AnyP::ProtocolType() const { return theScheme_; }
    // XXX: does not account for comparison of unknown schemes (by image)
    bool operator != (AnyP::ProtocolType const & aProtocol) const { return theScheme_ != aProtocol; }

    /** Get a char string representation of the scheme.
     * Does not include the ':' or "://" terminators.
     */
    SBuf image() const {return image_;}

    Port defaultPort() const;

    /// initializes down-cased protocol scheme names array
    static void Init();

    /// \returns ProtocolType for the given scheme name or PROTO_UNKNOWN
    static AnyP::ProtocolType FindProtocolType(const SBuf &);

private:
    /// optimization: stores down-cased protocol scheme names, copied from
    /// AnyP::ProtocolType_str
    static LowercaseSchemeNames LowercaseSchemeNames_;

    /// This is a typecode pointer into the enum/registry of protocols handled.
    AnyP::ProtocolType theScheme_;

    /// the string representation
    SBuf image_;
};

inline std::ostream &
operator <<(std::ostream &os, const UriScheme &scheme)
{
    os << scheme.image();
    return os;
}

} // namespace AnyP

#endif /* SQUID_SRC_ANYP_URISCHEME_H */

