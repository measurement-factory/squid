/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    Adaptation */

#include "squid.h"
#include "adaptation/Message.h"
#include "base/TextException.h"
#include "BodyPipe.h"
#include "http/Message.h"

Adaptation::Message::Message(Header *aHeader): header(nullptr)
{
    set(aHeader);
}

Adaptation::Message::~Message()
{
    clear();
}

void
Adaptation::Message::clear()
{
    HTTPMSGUNLOCK(header);
    body_pipe = nullptr;
}

void
Adaptation::Message::set(Header *aHeader)
{
    clear();
    if (aHeader) {
        header = aHeader;
        HTTPMSGLOCK(header);
        body_pipe = header->body_pipe;
    }
}

