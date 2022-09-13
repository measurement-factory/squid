/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Assure.h"
#include "Debug.h"
#include "error/Details.h"
#include "sbuf/SBuf.h"

void
ErrorDetails::Merge(ErrorDetailPointer &storage, const ErrorDetailPointer &later)
{
    if (storage == later)
        return; // we re-discovered an already stored detail object

    const auto earlier = storage;

    // XXX: Inconsistent storage/earlier naming
    Assure(earlier);
    const auto earlierGroup = dynamic_cast<ErrorDetails*>(storage.getRaw());

    Assure(later);
    const auto laterGroup = dynamic_cast<const ErrorDetails*>(later.getRaw());

    if (!earlierGroup && !laterGroup) {
        debugs(4, 7, "1+1");
        storage = new ErrorDetails(earlier, later);
        return;
    }

    if (earlierGroup) {
        if (laterGroup)
            earlierGroup->details.insert(earlierGroup->details.end(), laterGroup->details.begin(), laterGroup->details.end()); // n + k
        else
            earlierGroup->details.push_back(later); // n + 1
        debugs(4, 7, earlierGroup->details.size());
        return;
    }

    // 1 + n
    Assure(laterGroup); // or we would have handled the two singles above
    Assure(laterGroup->details.size()); // front() and begin()+1 below are valid
    const RefCount<ErrorDetails> result = new ErrorDetails(earlier, laterGroup->details.front());
    result->details.insert(result->details.end(), laterGroup->details.begin() + 1, laterGroup->details.end());
    storage = result;
    debugs(4, 7, result->details.size());
}

ErrorDetails::ErrorDetails(const ErrorDetailPointer &earlier, const ErrorDetailPointer &later):
    details({earlier, later})
{
}

SBuf
ErrorDetails::brief() const
{
    SBuf buf;
    for (const auto detail: details) {
        if (buf.length())
            buf.append('+');
        buf.append(detail->brief());
    }
    return buf;
}

SBuf
ErrorDetails::verbose(const HttpRequestPointer &request) const
{
    SBuf buf;
    for (const auto detail: details) {
        if (buf.length()) {
            static const SBuf delimiter("; ");
            buf.append(delimiter);
        }
        buf.append(detail->verbose(request));
    }
    return buf;
}
