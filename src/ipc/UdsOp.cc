/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "compat/socket.h"
#include "ipc/UdsOp.h"

#include <deque>

typedef CbcPointer<Ipc::UdsSender> UdsSenderPointer;

class UdsSenderMessage
{
public:
    UdsSenderMessage(const String &addr, const Ipc::TypedMsgHdr &msg):
        destinationAddr(addr),
        message(msg),
        codeContext(CodeContext::Current())
    {}

    const String destinationAddr;
    const Ipc::TypedMsgHdr message;
    CodeContextPointer codeContext;
};

/// Queues IPC messages before passing them to a UdsSender job.
/// Guarantees only one UdsSender at a time.
class UdsSenderMessages
{
public:
    /// adds a message to the queue
    void insert(const String &addr, const Ipc::TypedMsgHdr &msg);

    ///spawns an UdsSender job with the head queue element
    void kick();

private:
    /// the last started UdsSender job
    UdsSenderPointer sender;
    /// queued messages as FIFO
    std::deque<UdsSenderMessage> queue;
};

static UdsSenderMessages QueuedMessages;

void
UdsSenderMessages::insert(const String &addr, const Ipc::TypedMsgHdr &msg)
{
    queue.emplace_back(addr, msg);
}

void
UdsSenderMessages::kick()
{
    debugs(54, 5, "queue size: " << queue.size());

    if (queue.empty())
        return;

    if (sender.valid()) {
        debugs(54, 5, "the previous UdsSender is still executing");
        return;
    }

    const auto &current = queue.front();
    CallBack(current.codeContext, [&] {
        sender = new Ipc::UdsSender(current.destinationAddr, current.message);
        AsyncJob::Start(sender.get());
    });
    queue.pop_front();
}

// an AsyncCall dialer for UdsSenderMessages::kick()
class UdsDialer: public CallDialer
{
public:
    typedef void (UdsSenderMessages::*Method)();
    UdsDialer(UdsSenderMessages *initiator, Method method): initiator_(initiator), method_() {}

    virtual void print(std::ostream &os) const { os << "()"; }
    virtual bool canDial(AsyncCall &) const { return true; }
    virtual void dial(AsyncCall &) { (initiator_->*method_)(); }

public:
    UdsSenderMessages *initiator_;
    Method method_;
};

Ipc::UdsOp::UdsOp(const String& pathAddr):
    AsyncJob("Ipc::UdsOp"),
    address(PathToAddress(pathAddr)),
    options(COMM_NONBLOCKING)
{
    debugs(54, 5, '[' << this << "] pathAddr=" << pathAddr);
}

Ipc::UdsOp::~UdsOp()
{
    debugs(54, 5, '[' << this << ']');
    if (Comm::IsConnOpen(conn_))
        conn_->close();
    conn_ = nullptr;
}

void Ipc::UdsOp::setOptions(int newOptions)
{
    options = newOptions;
}

Comm::ConnectionPointer &
Ipc::UdsOp::conn()
{
    if (!Comm::IsConnOpen(conn_)) {
        if (options & COMM_DOBIND)
            unlink(address.sun_path);
        if (conn_ == nullptr)
            conn_ = new Comm::Connection;
        conn_->fd = comm_open_uds(SOCK_DGRAM, 0, &address, options);
        Must(Comm::IsConnOpen(conn_));
    }
    return conn_;
}

void Ipc::UdsOp::setTimeout(time_t seconds, const char *handlerName)
{
    typedef CommCbMemFunT<UdsOp, CommTimeoutCbParams> Dialer;
    AsyncCall::Pointer handler = asyncCall(54,5, handlerName,
                                           Dialer(CbcPointer<UdsOp>(this), &UdsOp::noteTimeout));
    commSetConnTimeout(conn(), seconds, handler);
}

void Ipc::UdsOp::clearTimeout()
{
    commUnsetConnTimeout(conn());
}

void Ipc::UdsOp::noteTimeout(const CommTimeoutCbParams &)
{
    timedout(); // our kid handles communication timeout
}

struct sockaddr_un
Ipc::PathToAddress(const String& pathAddr) {
    assert(pathAddr.size() != 0);
    struct sockaddr_un unixAddr;
    memset(&unixAddr, 0, sizeof(unixAddr));
    unixAddr.sun_family = AF_LOCAL;
    xstrncpy(unixAddr.sun_path, pathAddr.termedBuf(), sizeof(unixAddr.sun_path));
    return unixAddr;
}

CBDATA_NAMESPACED_CLASS_INIT(Ipc, UdsSender);

Ipc::UdsSender::UdsSender(const String& pathAddr, const TypedMsgHdr& aMessage):
    UdsOp(pathAddr),
    codeContext(CodeContext::Current()),
    message(aMessage),
    retries(10), // TODO: make configurable?
    timeout(10), // TODO: make configurable?
    sleeping(false),
    writing(false)
{
    message.address(address);
}

void Ipc::UdsSender::swanSong()
{
    // did we abort while waiting between retries?
    if (sleeping)
        cancelSleep();

    AsyncCall::Pointer call = asyncCall(54, 5, "UdsSenderMessages::kick", UdsDialer(&QueuedMessages, &UdsSenderMessages::kick));
    ScheduleCallHere(call);

    UdsOp::swanSong();
}

void Ipc::UdsSender::start()
{
    UdsOp::start();
    write();
    if (timeout > 0)
        setTimeout(timeout, "Ipc::UdsSender::noteTimeout");
}

bool Ipc::UdsSender::doneAll() const
{
    return !writing && !sleeping && UdsOp::doneAll();
}

void Ipc::UdsSender::write()
{
    debugs(54, 5, MYNAME);
    typedef CommCbMemFunT<UdsSender, CommIoCbParams> Dialer;
    AsyncCall::Pointer writeHandler = JobCallback(54, 5,
                                      Dialer, this, UdsSender::wrote);
    Comm::Write(conn(), message.raw(), message.size(), writeHandler, nullptr);
    writing = true;
}

void Ipc::UdsSender::wrote(const CommIoCbParams& params)
{
    debugs(54, 5, params.conn << " flag " << params.flag << " retries " << retries << " [" << this << ']');
    writing = false;
    if (params.flag != Comm::OK && retries-- > 0) {
        // perhaps a fresh connection and more time will help?
        conn()->close();
        startSleep();
    }
}

/// pause for a while before resending the message
void Ipc::UdsSender::startSleep()
{
    Must(!sleeping);
    sleeping = true;
    eventAdd("Ipc::UdsSender::DelayedRetry",
             Ipc::UdsSender::DelayedRetry,
             new Pointer(this), 1, 0, false); // TODO: Use Fibonacci increments
}

/// stop sleeping (or do nothing if we were not)
void Ipc::UdsSender::cancelSleep()
{
    if (sleeping) {
        // Why not delete the event? See Comm::ConnOpener::cancelSleep().
        sleeping = false;
        debugs(54, 9, "stops sleeping");
    }
}

/// legacy wrapper for Ipc::UdsSender::delayedRetry()
void Ipc::UdsSender::DelayedRetry(void *data)
{
    Pointer *ptr = static_cast<Pointer*>(data);
    assert(ptr);
    if (UdsSender *us = dynamic_cast<UdsSender*>(ptr->valid())) {
        CallBack(us->codeContext, [&us] {
            CallJobHere(54, 4, us, UdsSender, delayedRetry);
        });
    }
    delete ptr;
}

/// make another sending attempt after a pause
void Ipc::UdsSender::delayedRetry()
{
    debugs(54, 5, sleeping);
    if (sleeping) {
        sleeping = false;
        write(); // reopens the connection if needed
    }
}

void Ipc::UdsSender::timedout()
{
    debugs(54, 5, MYNAME);
    mustStop("timedout");
}

void Ipc::SendMessage(const String& toAddress, const TypedMsgHdr &message)
{
    QueuedMessages.insert(toAddress, message);
    QueuedMessages.kick();
}

const Comm::ConnectionPointer &
Ipc::ImportFdIntoComm(const Comm::ConnectionPointer &conn, int socktype, int protocol, Ipc::FdNoteId noteId)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (xgetsockname(conn->fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
        conn->remote = addr;
        struct addrinfo* addr_info = nullptr;
        conn->remote.getAddrInfo(addr_info);
        addr_info->ai_socktype = socktype;
        addr_info->ai_protocol = protocol;
        comm_import_opened(conn, Ipc::FdNote(noteId), addr_info);
        Ip::Address::FreeAddr(addr_info);
    } else {
        int xerrno = errno;
        debugs(54, DBG_CRITICAL, "ERROR: Ipc::ImportFdIntoComm: " << conn << ' ' << xstrerr(xerrno));
        conn->close();
    }
    return conn;
}

