/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "globals.h"
#include "helper/ChildConfig.h"
#include "Instance.h"
#include "Parsing.h"
#include "tools.h"

#include <cstring>

Helper::ChildConfig::ChildConfig():
    n_max(0),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0),
    queue_size(0),
    onPersistentOverload(actDie),
    defaultQueueSize(true)
{}

Helper::ChildConfig::ChildConfig(const unsigned int m):
    n_max(m),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0),
    queue_size(2 * m),
    onPersistentOverload(actDie),
    defaultQueueSize(true)
{}

Helper::ChildConfig &
Helper::ChildConfig::updateLimits(const Helper::ChildConfig &rhs)
{
    // Copy the limits only.
    // Preserve the local state values (n_running and n_active)
    n_max = rhs.n_max;
    n_startup = rhs.n_startup;
    n_idle = rhs.n_idle;
    concurrency = rhs.concurrency;
    queue_size = rhs.queue_size;
    onPersistentOverload = rhs.onPersistentOverload;
    defaultQueueSize = rhs.defaultQueueSize;
    return *this;
}

int
Helper::ChildConfig::needNew() const
{
    if (Instance::Starting() || reconfiguring || RotatingLogs) {
        // During startup, we are naturally guided by startup=n configuration.
        // During reconfiguration and log rotation, helpers are restarted (i.e.
        // shut down and started), so we use that configuration as well. During
        // startup and, in theory, when restarting helpers, we may be called
        // after some helpers have been activated already; account for those.
        return (n_startup > n_active) ? (n_startup - n_active) : 0;
    }

    /* keep a minimum of n_idle helpers free... */
    if ( (n_active + n_idle) < n_max) return n_idle;

    /* do not ever start more than n_max processes. */
    return (n_max - n_active);
}

void
Helper::ChildConfig::parseConfig()
{
    char const *token = ConfigParser::NextToken();

    if (!token) {
        self_destruct();
        return;
    }

    /* starts with a bare number for the max... back-compatible */
    n_max = xatoui(token);

    if (n_max < 1) {
        debugs(0, DBG_CRITICAL, "ERROR: The maximum number of processes cannot be less than 1.");
        self_destruct();
        return;
    }

    /* Parse extension options */
    for (; (token = ConfigParser::NextToken()) ;) {
        if (strncmp(token, "startup=", 8) == 0) {
            n_startup = xatoui(token + 8);
        } else if (strncmp(token, "idle=", 5) == 0) {
            n_idle = xatoui(token + 5);
            if (n_idle < 1) {
                debugs(0, DBG_CRITICAL, "WARNING: OVERRIDE: Using idle=0 for helpers causes request failures. Overriding to use idle=1 instead.");
                n_idle = 1;
            }
        } else if (strncmp(token, "concurrency=", 12) == 0) {
            concurrency = xatoui(token + 12);
        } else if (strncmp(token, "queue-size=", 11) == 0) {
            queue_size = xatoui(token + 11);
            defaultQueueSize = false;
        } else if (strncmp(token, "on-persistent-overload=", 23) == 0) {
            const SBuf action(token + 23);
            if (action.cmp("ERR") == 0)
                onPersistentOverload = actErr;
            else if (action.cmp("die") == 0)
                onPersistentOverload = actDie;
            else {
                debugs(0, DBG_CRITICAL, "ERROR: Unsupported on-persistent-overloaded action: " << action);
                self_destruct();
                return;
            }
        } else if (strncmp(token, "reservation-timeout=", 20) == 0)
            reservationTimeout = xatoui(token + 20);
        else {
            debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Undefined option: " << token << ".");
            self_destruct();
            return;
        }
    }

    if (n_startup && !IamWorkerProcess()) {
        debugs(0, 2, "non-worker kid overwrites startup=" << n_startup << " with startup=0");
        n_startup =0;
    }

    /* simple sanity. */

    if (n_startup > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING: OVERRIDE: Capping startup=" << n_startup << " to the defined maximum (" << n_max <<")");
        n_startup = n_max;
    }

    if (n_idle > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING: OVERRIDE: Capping idle=" << n_idle << " to the defined maximum (" << n_max <<")");
        n_idle = n_max;
    }

    if (defaultQueueSize)
        queue_size = 2 * n_max;
}

