/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "fatal.h"
#include "HttpHeaderRange.h"

#include <climits>

// TODO: refactor as cppunit test

// XXX: Misplaced
#define STUB_API "http/Message.cc"
#include "tests/STUB.h"
#include "http/Message.h"
#include "http/StatusLine.h"
Http::Message::Message(const http_hdr_owner_type owner): header(owner) { STUB; }
Http::Message::~Message() STUB
int Http::Message::httpMsgParseError() STUB_RETVAL(-1)
void Http::Message::hdrCacheInit() STUB
void Http::StatusLine::packInto(Packable*) const STUB
HttpHeader::HttpHeader(const http_hdr_owner_type anOwner): owner(anOwner), len(0), conflictingContentLength_(false) { STUB; }
HttpHeader::~HttpHeader() STUB

// XXX: Duplicates httpHeaderParseOffset() implementation in HttpHeaderTools.cc
// to avoid dragging heavy HttpHeaderTools.cc dependencies with that.
// #include "HttpHeaderTools.h"
bool httpHeaderParseOffset(char const*, long*, char**);
bool
httpHeaderParseOffset(const char *start, int64_t *value, char **endPtr)
{
    char *end = nullptr;
    errno = 0;
    const int64_t res = strtoll(start, &end, 10);
    if (errno && !res) {
        debugs(66, 7, "failed to parse malformed offset in " << start);
        return false;
    }
    if (errno == ERANGE && (res == LLONG_MIN || res == LLONG_MAX)) { // no overflow
        debugs(66, 7, "failed to parse huge offset in " << start);
        return false;
    }
    if (start == end) {
        debugs(66, 7, "failed to parse empty offset");
        return false;
    }
    *value = res;
    if (endPtr)
        *endPtr = end;
    debugs(66, 7, "offset " << start << " parsed as " << res);
    return true;
}

static void
testRangeParser(char const *rangestring)
{
    String aString (rangestring);
    HttpHdrRange *range = HttpHdrRange::ParseCreate (&aString);

    if (!range)
        exit(EXIT_FAILURE);

    HttpHdrRange copy(*range);

    assert (copy.specs.size() == range->specs.size());

    HttpHdrRange::iterator pos = range->begin();

    assert (*pos);

    delete range;
}

static HttpHdrRange *
rangeFromString(char const *rangestring)
{
    String aString (rangestring);
    HttpHdrRange *range = HttpHdrRange::ParseCreate (&aString);

    if (!range)
        exit(EXIT_FAILURE);

    return range;
}

static void
testRangeIter ()
{
    HttpHdrRange *range=rangeFromString("bytes=0-3, 1-, -2");
    assert (range->specs.size() == 3);
    size_t counter = 0;
    HttpHdrRange::iterator i = range->begin();

    while (i != range->end()) {
        ++counter;
        ++i;
    }

    assert (counter == 3);
    i = range->begin();
    assert (i - range->begin() == 0);
    ++i;
    assert (i - range->begin() == 1);
    assert (i - range->end() == -2);
}

static void
testRangeCanonization()
{
    HttpHdrRange *range=rangeFromString("bytes=0-3, 1-, -2");
    assert (range->specs.size() == 3);

    /* 0-3 needs a content length of 4 */
    /* This passes in the extant code - but should it? */

    if (!range->canonize(3))
        exit(EXIT_FAILURE);

    assert (range->specs.size() == 3);

    delete range;

    range=rangeFromString("bytes=0-3, 1-, -2");

    assert (range->specs.size() == 3);

    /* 0-3 needs a content length of 4 */
    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.size() == 1);

    /* 3-6 needs a content length of 4 or more */
    if (range->canonize(3))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=3-6");

    assert (range->specs.size() == 1);

    /* 3-6 needs a content length of 4 or more */
    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    delete range;

    range=rangeFromString("bytes=1-1,2-3");

    assert (range->specs.size()== 2);

    if (!range->canonize(4))
        exit(EXIT_FAILURE);

    assert (range->specs.size() == 2);

    delete range;
}

int
main(int, char **)
{
    try {
        Mem::Init();
        /* enable for debugging to console */
        // Debug::debugOptions = xstrdup("ALL,1 64,9");
        // Debug::BanCacheLogUse();
        testRangeParser("bytes=0-3");
        testRangeParser("bytes=-3");
        testRangeParser("bytes=1-");
        testRangeParser("bytes=0-3, 1-, -2");
        testRangeIter();
        testRangeCanonization();
    } catch (const std::exception &e) {
        printf("Error: dying from an unhandled exception: %s\n", e.what());
        return EXIT_FAILURE;
    } catch (...) {
        printf("Error: dying from an unhandled exception.\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

