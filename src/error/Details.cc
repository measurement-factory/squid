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
ErrorDetails::Merge(ErrorDetailPointer &storage, const ErrorDetailPointer &latest)
{
    if (!latest)
        return; // x + 0

    if (!storage) {
        storage = latest; // 0 + x
        return;
    }

    // XXX: Weed out duplicates at the individual detail level instead.
    if (storage == latest)
        return; // we re-discovered an already stored detail object

    Assure(storage);
    const auto storedGroup = dynamic_cast<ErrorDetails*>(storage.getRaw());

    Assure(latest);
    const auto latestGroup = dynamic_cast<const ErrorDetails*>(latest.getRaw());

    if (!storedGroup && !latestGroup) {
        debugs(4, 7, "1+1");
        storage = new ErrorDetails(storage, latest);
        return;
    }

    if (storedGroup) {
        if (latestGroup)
            storedGroup->details.insert(storedGroup->details.end(), latestGroup->details.begin(), latestGroup->details.end()); // n + k
        else
            storedGroup->details.push_back(latest); // n + 1
        debugs(4, 7, storedGroup->details.size());
        return;
    }

    // 1 + n
    Assure(latestGroup); // or we would have handled the two singles above
    Assure(latestGroup->details.size()); // front() and begin()+1 below are valid
    const RefCount<ErrorDetails> result = new ErrorDetails(storage, latestGroup->details.front());
    result->details.insert(result->details.end(), latestGroup->details.begin() + 1, latestGroup->details.end());
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
