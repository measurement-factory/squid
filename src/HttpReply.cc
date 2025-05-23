/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 58    HTTP Reply (Response) */

#include "squid.h"
#include "acl/AclSizeLimit.h"
#include "acl/FilledChecklist.h"
#include "base/EnumIterator.h"
#include "globals.h"
#include "http/ContentLengthInterpreter.h"
#include "HttpBody.h"
#include "HttpHdrCc.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "Store.h"
#include "StrList.h"

HttpReply::HttpReply():
    Http::Message(hoReply),
    date(0),
    last_modified(0),
    expires(0),
    surrogate_control(nullptr),
    keep_alive(0),
    protoPrefix("HTTP/"),
    bodySizeMax(-2),
    content_range(nullptr)
{
    init();
}

HttpReply::~HttpReply()
{
    if (do_clean)
        clean();
}

void
HttpReply::init()
{
    hdrCacheInit();
    sline.init();
    pstate = Http::Message::psReadyToParseStartLine;
    do_clean = true;
}

void HttpReply::reset()
{

    // reset should not reset the protocol; could have made protoPrefix a
    // virtual function instead, but it is not clear whether virtual methods
    // are allowed with MEMPROXY_CLASS() and whether some cbdata void*
    // conversions are not going to kill virtual tables
    const String pfx = protoPrefix;
    clean();
    init();
    protoPrefix = pfx;
}

void
HttpReply::clean()
{
    // we used to assert that the pipe is NULL, but now the message only
    // points to a pipe that is owned and initiated by another object.
    body_pipe = nullptr;

    body.clear();
    hdrCacheClean();
    header.clean();
    sline.clean();
    bodySizeMax = -2; // hack: make calculatedBodySizeMax() false
}

void
HttpReply::packHeadersUsingFastPacker(Packable &p) const
{
    sline.packInto(&p);
    header.packInto(&p);
    p.append("\r\n", 2);
}

void
HttpReply::packHeadersUsingSlowPacker(Packable &p) const
{
    MemBuf buf;
    buf.init();
    packHeadersUsingFastPacker(buf);
    p.append(buf.content(), buf.contentSize());
}

void
HttpReply::packInto(MemBuf &buf) const
{
    packHeadersUsingFastPacker(buf);
    body.packInto(&buf);
}

/* create memBuf, create mem-based packer, pack, destroy packer, return MemBuf */
MemBuf *
HttpReply::pack() const
{
    MemBuf *mb = new MemBuf;
    mb->init();
    packInto(*mb);
    return mb;
}

HttpReplyPointer
HttpReply::MakeConnectionEstablished() {

    HttpReplyPointer rep(new HttpReply);
    rep->sline.set(Http::ProtocolVersion(), Http::scOkay, "Connection established");
    return rep;
}

HttpReplyPointer
HttpReply::make304() const
{
    static const Http::HdrType ImsEntries[] = {Http::HdrType::DATE, Http::HdrType::CONTENT_TYPE, Http::HdrType::EXPIRES, Http::HdrType::LAST_MODIFIED, /* eof */ Http::HdrType::OTHER};

    const HttpReplyPointer rv(new HttpReply);
    int t;
    HttpHeaderEntry *e;

    /* rv->content_length; */
    rv->date = date;
    rv->last_modified = last_modified;
    rv->expires = expires;
    rv->content_type = content_type;
    /* rv->content_range */
    /* rv->keep_alive */
    rv->sline.set(Http::ProtocolVersion(), Http::scNotModified, nullptr);

    for (t = 0; ImsEntries[t] != Http::HdrType::OTHER; ++t) {
        if ((e = header.findEntry(ImsEntries[t])))
            rv->header.addEntry(e->clone());
    }

    if (cache_control)
        rv->putCc(*cache_control);

    /* rv->body */
    return rv;
}

MemBuf *
HttpReply::packed304Reply() const
{
    /* Not as efficient as skipping the header duplication,
     * but easier to maintain
     */
    const auto temp = make304();
    MemBuf *rv = temp->pack();
    return rv;
}

void
HttpReply::setHeaders(Http::StatusCode status, const char *reason,
                      const char *ctype, int64_t clen, time_t lmt, time_t expiresTime)
{
    HttpHeader *hdr;
    sline.set(Http::ProtocolVersion(), status, reason);
    hdr = &header;
    hdr->putStr(Http::HdrType::SERVER, visible_appname_string);
    hdr->putStr(Http::HdrType::MIME_VERSION, "1.0");
    hdr->putTime(Http::HdrType::DATE, squid_curtime);

    if (ctype) {
        hdr->putStr(Http::HdrType::CONTENT_TYPE, ctype);
        content_type = ctype;
    } else
        content_type = String();

    if (clen >= 0)
        hdr->putInt64(Http::HdrType::CONTENT_LENGTH, clen);

    if (expiresTime >= 0)
        hdr->putTime(Http::HdrType::EXPIRES, expiresTime);

    if (lmt > 0)        /* this used to be lmt != 0 @?@ */
        hdr->putTime(Http::HdrType::LAST_MODIFIED, lmt);

    date = squid_curtime;

    content_length = clen;

    expires = expiresTime;

    last_modified = lmt;
}

void
HttpReply::redirect(Http::StatusCode status, const char *loc)
{
    HttpHeader *hdr;
    sline.set(Http::ProtocolVersion(), status, nullptr);
    hdr = &header;
    hdr->putStr(Http::HdrType::SERVER, visible_appname_string);
    hdr->putTime(Http::HdrType::DATE, squid_curtime);
    hdr->putInt64(Http::HdrType::CONTENT_LENGTH, 0);
    hdr->putStr(Http::HdrType::LOCATION, loc);
    date = squid_curtime;
    content_length = 0;
}

/* compare the validators of two replies.
 * 1 = they match
 * 0 = they do not match
 */
int
HttpReply::validatorsMatch(HttpReply const * otherRep) const
{
    String one,two;
    assert (otherRep);
    /* Numbers first - easiest to check */
    /* Content-Length */
    /* TODO: remove -1 bypass */

    if (content_length != otherRep->content_length
            && content_length > -1 &&
            otherRep->content_length > -1)
        return 0;

    /* ETag */
    one = header.getStrOrList(Http::HdrType::ETAG);

    two = otherRep->header.getStrOrList(Http::HdrType::ETAG);

    if (one.size()==0 || two.size()==0 || one.caseCmp(two)!=0 ) {
        one.clean();
        two.clean();
        return 0;
    }

    if (last_modified != otherRep->last_modified)
        return 0;

    /* MD5 */
    one = header.getStrOrList(Http::HdrType::CONTENT_MD5);

    two = otherRep->header.getStrOrList(Http::HdrType::CONTENT_MD5);

    if (one.size()==0 || two.size()==0 || one.caseCmp(two)!=0 ) {
        one.clean();
        two.clean();
        return 0;
    }

    return 1;
}

HttpReply::Pointer
HttpReply::recreateOnNotModified(const HttpReply &reply304) const
{
    // If enough 304s do not update, then this expensive checking is cheaper
    // than blindly storing reply prefix identical to the already stored one.
    if (!header.needUpdate(&reply304.header))
        return nullptr;

    const Pointer cloned = clone();
    cloned->header.update(&reply304.header);
    cloned->hdrCacheClean();
    cloned->header.compact();
    cloned->hdrCacheInit();
    return cloned;
}

/* internal routines */

time_t
HttpReply::hdrExpirationTime()
{
    /* The s-maxage and max-age directive takes priority over Expires */

    if (cache_control) {
        int maxAge = -1;
        /*
         * Conservatively handle the case when we have a max-age
         * header, but no Date for reference?
         */
        if (cache_control->hasSMaxAge(&maxAge) || cache_control->hasMaxAge(&maxAge))
            return (date >= 0) ? date + maxAge : squid_curtime;
    }

    if (Config.onoff.vary_ignore_expire &&
            header.has(Http::HdrType::VARY)) {
        const time_t d = header.getTime(Http::HdrType::DATE);
        const time_t e = header.getTime(Http::HdrType::EXPIRES);

        if (d == e)
            return -1;
    }

    if (header.has(Http::HdrType::EXPIRES)) {
        const time_t e = header.getTime(Http::HdrType::EXPIRES);
        /*
         * HTTP/1.0 says that robust implementations should consider
         * bad or malformed Expires header as equivalent to "expires
         * immediately."
         */
        return e < 0 ? squid_curtime : e;
    }

    return -1;
}

/* sync this routine when you update HttpReply struct */
void
HttpReply::hdrCacheInit()
{
    Http::Message::hdrCacheInit();

    http_ver = sline.version;
    content_length = header.getInt64(Http::HdrType::CONTENT_LENGTH);
    date = header.getTime(Http::HdrType::DATE);
    last_modified = header.getTime(Http::HdrType::LAST_MODIFIED);
    surrogate_control = header.getSc();
    content_range = (sline.status() == Http::scPartialContent) ?
                    header.getContRange() : nullptr;
    keep_alive = persistent() ? 1 : 0;
    const char *str = header.getStr(Http::HdrType::CONTENT_TYPE);

    if (str)
        content_type.assign(str, strcspn(str, ";\t "));
    else
        content_type = String();

    /* be sure to set expires after date and cache-control */
    expires = hdrExpirationTime();
}

const HttpHdrContRange *
HttpReply::contentRange() const
{
    assert(!content_range || sline.status() == Http::scPartialContent);
    return content_range;
}

/* sync this routine when you update HttpReply struct */
void
HttpReply::hdrCacheClean()
{
    content_type.clean();

    if (cache_control) {
        delete cache_control;
        cache_control = nullptr;
    }

    if (surrogate_control) {
        delete surrogate_control;
        surrogate_control = nullptr;
    }

    if (content_range) {
        delete content_range;
        content_range = nullptr;
    }
}

/*
 * Returns the body size of a HTTP response
 */
int64_t
HttpReply::bodySize(const HttpRequestMethod& method) const
{
    if (sline.version.major < 1)
        return -1;
    else if (method.id() == Http::METHOD_HEAD)
        return 0;
    else if (sline.status() == Http::scOkay)
        (void) 0;       /* common case, continue */
    else if (sline.status() == Http::scNoContent)
        return 0;
    else if (sline.status() == Http::scNotModified)
        return 0;
    else if (sline.status() < Http::scOkay)
        return 0;

    return content_length;
}

/**
 * Checks the first line of an HTTP Reply is valid.
 * currently only checks "HTTP/" exists.
 *
 * NP: not all error cases are detected yet. Some are left for detection later in parse.
 */
bool
HttpReply::sanityCheckStartLine(const char *buf, const size_t hdr_len, Http::StatusCode *error)
{
    // hack warning: using psize instead of size here due to type mismatches with MemBuf.

    // content is long enough to possibly hold a reply
    // 4 being magic size of a 3-digit number plus space delimiter
    if (hdr_len < (size_t)(protoPrefix.psize() + 4)) {
        if (hdr_len > 0) {
            debugs(58, 3, "Too small reply header (" << hdr_len << " bytes)");
            *error = Http::scInvalidHeader;
        }
        return false;
    }

    int pos;
    // catch missing or mismatched protocol identifier
    // allow special-case for ICY protocol (non-HTTP identifier) in response to faked HTTP request.
    if (strncmp(buf, "ICY", 3) == 0) {
        protoPrefix = "ICY";
        pos = protoPrefix.psize();
    } else {

        if (protoPrefix.cmp(buf, protoPrefix.size()) != 0) {
            debugs(58, 3, "missing protocol prefix (" << protoPrefix << ") in '" << buf << "'");
            *error = Http::scInvalidHeader;
            return false;
        }

        // catch missing or negative status value (negative '-' is not a digit)
        pos = protoPrefix.psize();

        // skip arbitrary number of digits and a dot in the version portion
        while ((size_t)pos <= hdr_len && (*(buf+pos) == '.' || xisdigit(*(buf+pos)) ) ) ++pos;

        // catch missing version info
        if (pos == protoPrefix.psize()) {
            debugs(58, 3, "missing protocol version numbers (ie. " << protoPrefix << "/1.0) in '" << buf << "'");
            *error = Http::scInvalidHeader;
            return false;
        }
    }

    // skip arbitrary number of spaces...
    while ((size_t)pos <= hdr_len && (char)*(buf+pos) == ' ') ++pos;

    if ((size_t)pos < hdr_len && !xisdigit(*(buf+pos))) {
        debugs(58, 3, "missing or invalid status number in '" << buf << "'");
        *error = Http::scInvalidHeader;
        return false;
    }

    return true;
}

bool
HttpReply::parseFirstLine(const char *blk_start, const char *blk_end)
{
    return sline.parse(protoPrefix, blk_start, blk_end);
}

size_t
HttpReply::parseTerminatedPrefix(const char * const terminatedBuf, const size_t bufSize)
{
    auto error = Http::scNone;
    const bool eof = false; // TODO: Remove after removing atEnd from HttpHeader::parse()
    if (parse(terminatedBuf, bufSize, eof, &error)) {
        debugs(58, 7, "success after accumulating " << bufSize << " bytes and parsing " << hdr_sz);
        Assure(pstate == Http::Message::psParsed);
        Assure(hdr_sz > 0);
        Assure(!Less(bufSize, hdr_sz)); // cannot parse more bytes than we have
        return hdr_sz; // success
    }

    Assure(pstate != Http::Message::psParsed);
    hdr_sz = 0;

    if (error) {
        throw TextException(ToSBuf("failed to parse HTTP headers",
                                   Debug::Extra, "parser error code: ", error,
                                   Debug::Extra, "accumulated unparsed bytes: ", bufSize,
                                   Debug::Extra, "reply_header_max_size: ", Config.maxReplyHeaderSize),
                            Here());
    }

    debugs(58, 3, "need more bytes after accumulating " << bufSize << " out of " << Config.maxReplyHeaderSize);

    // the parse() call above enforces Config.maxReplyHeaderSize limit
    // XXX: Make this a strict comparison after fixing Http::Message::parse() enforcement
    Assure(bufSize <= Config.maxReplyHeaderSize);
    return 0; // parsed nothing, need more data
}

size_t
HttpReply::prefixLen() const
{
    return sline.packedLength() + header.len + 2;
}

void
HttpReply::configureContentLengthInterpreter(Http::ContentLengthInterpreter &interpreter)
{
    interpreter.applyStatusCodeRules(sline.status());
}

bool
HttpReply::parseHeader(Http1::Parser &hp)
{
    Http::ContentLengthInterpreter clen;
    return Message::parseHeader(hp, clen);
}

/* handy: resets and returns -1 */
int
HttpReply::httpMsgParseError()
{
    int result(Http::Message::httpMsgParseError());
    /* indicate an error in the status line */
    sline.set(Http::ProtocolVersion(), Http::scInvalidHeader);
    return result;
}

/*
 * Indicate whether or not we would usually expect an entity-body
 * along with this response
 */
bool
HttpReply::expectingBody(const HttpRequestMethod& req_method, int64_t& theSize) const
{
    bool expectBody = true;

    if (req_method == Http::METHOD_HEAD)
        expectBody = false;
    else if (sline.status() == Http::scNoContent)
        expectBody = false;
    else if (sline.status() == Http::scNotModified)
        expectBody = false;
    // TODO: Consider assuming that gray-area 0xx responses have bodies, like 9xx responses.
    else if (sline.status() < Http::scOkay)
        expectBody = false;
    else
        expectBody = true;

    if (expectBody) {
        if (header.chunked())
            theSize = -1;
        else if (content_length >= 0)
            theSize = content_length;
        else
            theSize = -1;
    }

    return expectBody;
}

bool
HttpReply::receivedBodyTooLarge(HttpRequest& request, int64_t receivedSize)
{
    calcMaxBodySize(request);
    debugs(58, 3, receivedSize << " >? " << bodySizeMax);
    return bodySizeMax >= 0 && receivedSize > bodySizeMax;
}

bool
HttpReply::expectedBodyTooLarge(HttpRequest& request)
{
    calcMaxBodySize(request);
    debugs(58, 7, "bodySizeMax=" << bodySizeMax);

    if (bodySizeMax < 0) // no body size limit
        return false;

    int64_t expectedSize = -1;
    if (!expectingBody(request.method, expectedSize))
        return false;

    debugs(58, 6, expectedSize << " >? " << bodySizeMax);

    if (expectedSize < 0) // expecting body of an unknown length
        return false;

    return expectedSize > bodySizeMax;
}

void
HttpReply::calcMaxBodySize(HttpRequest& request) const
{
    // hack: -2 is used as "we have not calculated max body size yet" state
    if (bodySizeMax != -2) // already tried
        return;
    bodySizeMax = -1;

    // short-circuit ACL testing if there are none configured
    if (!Config.ReplyBodySize)
        return;

    ACLFilledChecklist ch(nullptr, &request);
    ch.updateReply(this);
    for (AclSizeLimit *l = Config.ReplyBodySize; l; l = l -> next) {
        /* if there is no ACL list or if the ACLs listed match use this size value */
        if (!l->aclList || ch.fastCheck(l->aclList).allowed()) {
            debugs(58, 4, "bodySizeMax=" << bodySizeMax);
            bodySizeMax = l->size; // may be -1
            break;
        }
    }
}

// XXX: check that this is sufficient for eCAP cloning
HttpReply *
HttpReply::clone() const
{
    HttpReply *rep = new HttpReply();
    rep->sline = sline; // used in hdrCacheInit() call below
    rep->header.append(&header);
    rep->hdrCacheInit();
    rep->hdr_sz = hdr_sz;
    rep->http_ver = http_ver;
    rep->pstate = pstate;
    rep->body_pipe = body_pipe;

    // keep_alive is handled in hdrCacheInit()
    return rep;
}

bool
HttpReply::inheritProperties(const Http::Message *aMsg)
{
    const HttpReply *aRep = dynamic_cast<const HttpReply*>(aMsg);
    if (!aRep)
        return false;
    keep_alive = aRep->keep_alive;
    sources = aRep->sources;
    return true;
}

bool
HttpReply::olderThan(const HttpReply *them) const
{
    if (!them || !them->date || !date)
        return false;
    return date < them->date;
}

void
HttpReply::removeIrrelevantContentLength() {
    if (Http::ProhibitsContentLength(sline.status()))
        if (header.delById(Http::HdrType::CONTENT_LENGTH))
            debugs(58, 3, "Removing unexpected Content-Length header");
}

