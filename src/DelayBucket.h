/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DELAYBUCKET_H
#define SQUID_DELAYBUCKET_H

class DelaySpec;
class StoreEntry;

/* don't use remote storage for these */

/// \ingroup DelayPoolsAPI
class DelayBucket
{

public:
    typedef int BucketLevel;

    DelayBucket() : level_(0) {}

    BucketLevel const& level() const { return level_; }

    BucketLevel &level() { return level_; }

    void stats(StoreEntry *)const;
    void update (DelaySpec const &, int incr);
    BucketLevel bytesWanted(BucketLevel min, BucketLevel max) const;
    void bytesIn(BucketLevel qty);
    void init (DelaySpec const &);

private:
    BucketLevel level_;
};

#endif /* SQUID_DELAYBUCKET_H */

