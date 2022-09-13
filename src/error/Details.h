/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for detailss.
 */

#ifndef _SQUID_SRC_ERROR_DETAILS_H
#define _SQUID_SRC_ERROR_DETAILS_H

#include "error/Detail.h"

#include <vector>

/// multiple details of a single error
class ErrorDetails: public ErrorDetail
{
public:
    // our "canonical order" is approximate discovery (e.g., Error::update()) order

    /// Combines error details preserving their canonical order. Each detail may
    /// be a single detail or an ErrorDetails object with multiple details.
    /// \param storage is used as the earlier detail and the result storage (optimization)
    static void Merge(ErrorDetailPointer &storage, const ErrorDetailPointer &later);

    virtual ~ErrorDetails() = default;

protected:
    // use ErrorDetails::Merge() instead
    ErrorDetails(const ErrorDetailPointer &earlier, const ErrorDetailPointer &later);

    /* ErrorDetail API */
    virtual SBuf brief() const;
    virtual SBuf verbose(const HttpRequestPointer &) const;

private:
    /// known detail(s) in canonical order
    std::vector<ErrorDetailPointer> details;
};

#endif /* _SQUID_SRC_ERROR_DETAILS_H */

