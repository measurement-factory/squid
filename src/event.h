/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_EVENT_H
#define SQUID_SRC_EVENT_H

#include "AsyncEngine.h"
#include "base/Packable.h"
#include "cbdata.h"
#include "mem/forward.h"

/* event scheduling facilities - run a callback after a given time period. */

typedef void EVH(void *);

/// implementation detail for eventAdd() and its variations below; do not call directly
void eventAdd_(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata);

/// calls `func(arg)` after a given time period without cbdata checks for `arg`
template <typename HandlerData>
void
eventAddBare(const char * const name, EVH * const func, const HandlerData arg, const double when, const int weight = 0)
{
    // callers with cbdata-protected `arg` should consider using eventAdd() instead
    static_assert(!CbdataProtected<HandlerData>());

    eventAdd_(name, func, arg, when, weight, false);
}

/// calls `func(arg)` after a given time period unless `arg` cbdata is or becomes invalid
template <typename HandlerData>
void
eventAdd(const char * const name, EVH * const func, const HandlerData arg, const double when, const int weight = 0)
{
    // callers with unprotected `arg` should consider using eventAddBare() instead
    static_assert(CbdataProtected<HandlerData>());

    eventAdd_(name, func, arg, when, weight, true);
}

/// Specialization for callers that have no handler data at all: No explicit
/// cbdata protection is needed for calls with explicit nullptr handlerData.
template <>
inline void
eventAdd(const char * const name, EVH * const func, std::nullptr_t, const double when, const int weight)
{
    eventAdd_(name, func, nullptr, when, weight, false);
}

/// eventAddIsh() implementation detail; do not call directly
double WhenIsh_(double deltaIsh);

template <typename HandlerData>
void
eventAddIsh(const char * const name, EVH * const func, const HandlerData arg, const double delta_ish, const int weight = 0)
{
    static_assert(CbdataProtected<HandlerData>());
    eventAdd_(name, func, arg, WhenIsh_(delta_ish), weight, true);
}

/// Specialization for callers that have no handler data at all: No explicit
/// cbdata protection is needed for calls with explicit nullptr handlerData.
template <>
inline void
eventAddIsh<std::nullptr_t>(const char * const name, EVH * const func, std::nullptr_t, const double delta_ish, const int weight)
{
    eventAdd_(name, func, nullptr, WhenIsh_(delta_ish), weight, true);
}

void eventDelete(EVH * func, void *arg);
void eventInit(void);
int eventFind(EVH *, void *);

class ev_entry
{
    MEMPROXY_CLASS(ev_entry);

public:
    ev_entry(char const * name, EVH * func, void *arg, double when, int weight, bool cbdata=true);
    ~ev_entry();
    const char *name;
    EVH *func;
    void *arg;
    double when;

    int weight;
    bool cbdata;

    ev_entry *next;
};

// manages time-based events
class EventScheduler : public AsyncEngine
{

public:
    EventScheduler();
    ~EventScheduler() override;
    /* cancel a scheduled but not dispatched event */
    void cancel(EVH * func, void * arg);
    /* clean up the used memory in the scheduler */
    void clean();
    /* either EVENT_IDLE or milliseconds remaining until the next event */
    int timeRemaining() const;
    /* cache manager output for the event queue */
    void dump(Packable *);
    /* find a scheduled event */
    bool find(EVH * func, void * arg);
    /* schedule a callback function to run in when seconds */
    void schedule(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata=true);
    int checkEvents(int timeout) override;
    static EventScheduler *GetInstance();

private:
    static EventScheduler _instance;
    ev_entry * tasks;
};

#endif /* SQUID_SRC_EVENT_H */

