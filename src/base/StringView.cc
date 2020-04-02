/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS string_views for details.
 */

#include "squid.h"
#include "base/StringView.h"

#include <iostream>

std::ostream &
operator <<(std::ostream &os, const StringView &view)
{
    if (const auto size = view.size())
        os.write(view.data(), size);
    return os;
}
