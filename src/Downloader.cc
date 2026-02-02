/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Raw.h"
#include "client_side.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "ClientRequestContext.h"
#include "Downloader.h"
#include "fatal.h"
#include "http/one/RequestParser.h"
#include "http/Stream.h"

CBDATA_CLASS_INIT(Downloader);

// TODO: Merge into Downloader.
/// Implements Store::UltimateClient API on behalf of the Downloader job.
class DownloaderContext: public Store::UltimateClient
{
    MEMPROXY_CLASS(DownloaderContext);

public:
    typedef RefCount<DownloaderContext> Pointer;

    explicit DownloaderContext(Downloader *);
    ~DownloaderContext() override;
    void finished();

    /* Store::UltimateClient API */
    void handleStoreReply(HttpReply *, StoreIOBuffer) override;
    uint64_t currentStoreReadingOffset() const override;

public:
    CbcPointer<Downloader> downloader;
    ClientHttpRequest *http;
};

DownloaderContext::DownloaderContext(Downloader * const dl):
    downloader(dl),
    http(new ClientHttpRequest(nullptr))
{
    debugs(33, 6, "DownloaderContext constructed, this=" << (void*)this);
}

DownloaderContext::~DownloaderContext()
{
    debugs(33, 6, "DownloaderContext destructed, this=" << (void*)this);
    if (http)
        finished();
}

void
DownloaderContext::finished()
{
    delete http;
    http = nullptr;
}

uint64_t
DownloaderContext::currentStoreReadingOffset() const
{
    return (http ? http->out.offset : 0);
}

std::ostream &
operator <<(std::ostream &os, const DownloaderAnswer &answer)
{
    os << "outcome=" << answer.outcome;
    if (answer.outcome == Http::scOkay)
        os << ", resource.size=" << answer.resource.length();
    return os;
}

Downloader::Downloader(const SBuf &url, const AsyncCallback<Answer> &cb, const MasterXactionPointer &mx, const unsigned int level):
    AsyncJob("Downloader"),
    url_(url),
    callback_(cb),
    level_(level),
    masterXaction_(mx)
{
}

Downloader::~Downloader()
{
    debugs(33, 6, this);
}

void
Downloader::swanSong()
{
    debugs(33, 6, this);

    if (callback_) // job-ending emergencies like handleStopRequest() or callException()
        callBack(Http::scInternalServerError);

    if (context_) {
        context_->finished();
        context_ = nullptr;
    }
}

bool
Downloader::doneAll() const
{
    return (!callback_ || callback_->canceled()) && AsyncJob::doneAll();
}

void
DownloaderContext::handleStoreReply(HttpReply * const rep, const StoreIOBuffer receivedData)
{
    if (downloader.valid())
        downloader->handleReply(http, rep, receivedData);
}

/// Initializes and starts the HTTP GET request to the remote server
bool
Downloader::buildRequest()
{
    const HttpRequestMethod method = Http::METHOD_GET;

    const auto request = HttpRequest::FromUrl(url_, masterXaction_, method);
    if (!request) {
        debugs(33, 5, "Invalid URI: " << url_);
        return false; //earlyError(...)
    }
    request->http_ver = Http::ProtocolVersion();
    request->header.putStr(Http::HdrType::HOST, request->url.host());
    request->header.putTime(Http::HdrType::DATE, squid_curtime);
    request->client_addr.setNoAddr();
#if FOLLOW_X_FORWARDED_FOR
    request->indirect_client_addr.setNoAddr();
#endif /* FOLLOW_X_FORWARDED_FOR */
    request->my_addr.setNoAddr();   /* undefined for internal requests */
    request->my_addr.port(0);
    request->downloader = this;

    debugs(11, 2, "HTTP Client Downloader " << this << "/" << id);
    debugs(11, 2, "HTTP Client REQUEST:\n---------\n" <<
           request->method << " " << url_ << " " << request->http_ver << "\n" <<
           "\n----------");

    context_ = Store::UltimateClient::Make<DownloaderContext>(this);
    const auto http = context_->http;
    http->initRequest(request);
    http->req_sz = 0;
    // XXX: performance regression. c_str() reallocates
    http->uri = xstrdup(url_.c_str());

    // Build a ClientRequestContext to start doCallouts
    http->calloutContext = new ClientRequestContext(http);
    http->doCallouts();
    return true;
}

void
Downloader::start()
{
    if (!buildRequest())
        callBack(Http::scInternalServerError);
}

void
Downloader::handleReply(ClientHttpRequest *http, HttpReply *reply, StoreIOBuffer receivedData)
{
    debugs(33, 4, "Received " << receivedData.length <<
           " object data, offset: " << receivedData.offset <<
           " error flag:" << receivedData.flags.error);

    const bool failed = receivedData.flags.error;
    if (failed) {
        callBack(Http::scInternalServerError);
        return;
    }

    const int64_t existingContent = reply ? reply->content_length : 0;
    const size_t maxSize = MaxObjectSize > SBuf::maxSize ? SBuf::maxSize : MaxObjectSize;
    const bool tooLarge = (existingContent > -1 && existingContent > static_cast<int64_t>(maxSize)) ||
                          (maxSize < object_.length()) ||
                          ((maxSize - object_.length()) < receivedData.length);

    if (tooLarge) {
        callBack(Http::scInternalServerError);
        return;
    }

    object_.append(receivedData.data, receivedData.length);
    http->out.size += receivedData.length;
    // XXX: Reject Content-Range responses! Their Store body offsets are
    // different than this and currentStoreReadingOffset() offset math assumes.
    http->out.offset += receivedData.length;

    switch (http->storeReader().replyStatus()) {
    case STREAM_NONE: {
        debugs(33, 3, "Get more data");
        http->readStoreResponse();
    }
    break;
    case STREAM_COMPLETE:
        debugs(33, 3, "Object data transfer successfully complete");
        callBack(Http::scOkay);
        break;
    case STREAM_UNPLANNED_COMPLETE:
        debugs(33, 3, "Object data transfer failed: STREAM_UNPLANNED_COMPLETE");
        callBack(Http::scInternalServerError);
        break;
    case STREAM_FAILED:
        debugs(33, 3, "Object data transfer failed: STREAM_FAILED");
        callBack(Http::scInternalServerError);
        break;
    default:
        fatal("unreachable code");
    }
}

void
Downloader::downloadFinished()
{
    debugs(33, 7, this);
    Must(done());
}

/// Schedules for execution the "callback" with parameters the status
/// and object.
void
Downloader::callBack(Http::StatusCode const statusCode)
{
    assert(callback_);
    auto &answer = callback_.answer();
    answer.outcome = statusCode;
    if (statusCode == Http::scOkay)
        answer.resource = object_;
    ScheduleCallHere(callback_.release());

    // We cannot deleteThis() because we may be called synchronously from
    // doCallouts() via handleReply() (XXX), and doCallouts() may crash if we
    // disappear. Instead, schedule an async call now so that later, when the
    // call firing code discovers a done() job, it deletes us.
    CallJobHere(33, 7, CbcPointer<Downloader>(this), Downloader, downloadFinished);
}

