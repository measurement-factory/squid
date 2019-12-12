/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

#if USE_IDENT

#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "globals.h"
#include "http/Stream.h"
#include "ident/AclIdent.h"
#include "ident/Ident.h"

ACLIdent::~ACLIdent()
{
    delete data;
}

ACLIdent::ACLIdent(ACLData<char const *> *newData, char const *newType) : data (newData), type_ (newType) {}

ACLIdent::ACLIdent (ACLIdent const &old) : data (old.data->clone()), type_ (old.type_)
{}

ACLIdent &
ACLIdent::operator= (ACLIdent const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    return *this;
}

char const *
ACLIdent::typeString() const
{
    return type_;
}

void
ACLIdent::parseFlags()
{
    ParseFlags(Acl::NoOptions(), data->supportedFlags());
}

void
ACLIdent::parse()
{
    if (!data) {
        debugs(28, 3, HERE << "current is null. Creating");
        data = new ACLUserData;
    }

    data->parse();
}

int
ACLIdent::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    if (checklist->rfc931[0])
        return data->match(checklist->rfc931);

    const auto mgr = checklist->clientConnectionManager();
    if (mgr && mgr->clientConnection && mgr->clientConnection->rfc931[0]) {
        return data->match(mgr->clientConnection->rfc931);
    } else if (mgr && Comm::IsConnOpen(mgr->clientConnection)) {
        if (checklist->goAsync(IdentLookup::Instance())) {
            debugs(28, 3, "switching to ident lookup state");
            return -1;
        }
        // else fall through to ACCESS_DUNNO failure below
    } else {
        debugs(28, DBG_IMPORTANT, HERE << "Can't start ident lookup. No client connection" );
        // fall through to ACCESS_DUNNO failure below
    }

    checklist->markFinished(ACCESS_DUNNO, "cannot start ident lookup");
    return -1;
}

SBufList
ACLIdent::dump() const
{
    return data->dump();
}

bool
ACLIdent::empty () const
{
    return data->empty();
}

ACL *
ACLIdent::clone() const
{
    return new ACLIdent(*this);
}

IdentLookup IdentLookup::instance_;

IdentLookup *
IdentLookup::Instance()
{
    return &instance_;
}

void
IdentLookup::checkForAsync(ACLChecklist *cl)const
{
    auto checklist = Filled(cl);
    const auto conn = checklist->clientConnectionManager();
    // check that ACLIdent::match() tested this lookup precondition
    assert(conn && Comm::IsConnOpen(conn->clientConnection));
    debugs(28, 3, HERE << "Doing ident lookup" );
    Ident::Start(conn->clientConnection, LookupDone, checklist);
}

void
IdentLookup::LookupDone(const char *ident, void *data)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));

    if (ident) {
        xstrncpy(checklist->rfc931, ident, USER_IDENT_SZ);
    } else {
        xstrncpy(checklist->rfc931, dash_str, USER_IDENT_SZ);
    }

    /*
     * Cache the ident result in the connection, to avoid redoing ident lookup
     * over and over on persistent connections
     */
    const auto mgr = checklist->clientConnectionManager();
    if (mgr && mgr->clientConnection && !mgr->clientConnection->rfc931[0])
        xstrncpy(mgr->clientConnection->rfc931, checklist->rfc931, USER_IDENT_SZ);

    checklist->resumeNonBlockingCheck(IdentLookup::Instance());
}

#endif /* USE_IDENT */

