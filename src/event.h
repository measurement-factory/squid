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
#include "mem/forward.h"

#include <type_traits>

// Check whether HandlerData is a pointer to a class with a toCbdata() method.
// Meant for use in static_assertion calls. When the caller supplies bad
// handlerData type, this code usually fails to compile even before our
// static_assert fails, but that is OK.
template <typename HandlerData>
constexpr bool
CbdataProtected()
{
    using HandlerDataClass = std::remove_pointer_t<HandlerData>;
    return std::is_member_function_pointer_v<decltype(&HandlerDataClass::toCbdata)>;
}

/* event scheduling facilities - run a callback after a given time period. */

typedef void EVH(void *);

/// eventAdd() implementation detail; do not call directly
void eventAdd_(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata);

/// calls func(arg) after a given time period (subject to optional cbdata checks)
/// \param cbdata whether to check (at call back time) cbdata validity; a failed
/// check disables a func(arg) call
template <typename HandlerData>
void
eventAdd(const char * const name, EVH * const func, const HandlerData arg, const double when, const int weight, const bool cbdata)
{
    // XXX: Cannot reject calls with false cbdata values for which
    // arg->toCbdata() exists. Such calls should probably use true cbdata.
    // XXX: Cannot reject calls with true cbdata values for which there is no
    // arg->toCbdata(). Such calls should probably use false cbdata.
    //
    // TODO: We could refactor to ban non-cbdata calls with non-nullptr
    // arguments, but it is best to switch event.h to AsyncCalls instead!
    eventAdd_(name, func, arg, when, weight, cbdata);
}

template <typename HandlerData>
void
eventAdd(const char * const name, EVH * const func, const HandlerData arg, const double when, const int weight)
{
    static_assert(CbdataProtected<HandlerData>());
    eventAdd_(name, func, arg, when, weight, true);
}

/// Specialization for callers that have no handler data at all: No explicit
/// cbdata protection is needed for calls with explicit nullptr handlerData.
template <>
inline void
eventAdd(const char *name, EVH * func, std::nullptr_t, double when, int weight)
{
    eventAdd_(name, func, nullptr, when, weight, false);
}


/// eventAddIsh() implementation detail; do not call directly
double WhenIsh_(double deltaIsh);

template <typename HandlerData>
void
eventAddIsh(const char * const name, EVH * const func, const HandlerData arg, const double delta_ish, const int weight)
{
    static_assert(CbdataProtected<HandlerData>());
    eventAdd_(name, func, arg, WhenIsh_(delta_ish), weight, true);
}

/// Specialization for callers that have no handler data at all: No explicit
/// cbdata protection is needed for calls with explicit nullptr handlerData.
template <>
inline void
eventAddIsh<std::nullptr_t>(const char *name, EVH * func, std::nullptr_t, double delta_ish, int weight)
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

