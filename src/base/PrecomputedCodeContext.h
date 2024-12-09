/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_PRECOMPUTEDCODECONTEXT_H
#define SQUID_SRC_BASE_PRECOMPUTEDCODECONTEXT_H

#include "base/CodeContext.h"
#include "base/InstanceId.h"
#include "sbuf/SBuf.h"

class MasterXaction;
template <class C> class RefCount;
typedef RefCount<MasterXaction> MasterXactionPointer;

/// CodeContext with constant details known at construction time
class PrecomputedCodeContext: public CodeContext
{
public:
    typedef RefCount<PrecomputedCodeContext> Pointer;

    PrecomputedCodeContext(const char *gist, const SBuf &detail, const MasterXactionPointer &mx);

    /* CodeContext API */
    ScopedId codeContextGist() const override;
    std::ostream &detailCodeContext(std::ostream &os) const override;

private:
    const char *gist_; ///< the id used in codeContextGist()
    const SBuf detail_; ///< the detail used in detailCodeContext()
    /// the corresponding master transaction detail, if any
    const SBuf masterXactionDetail_;
};

#endif /* SQUID_SRC_BASE_PRECOMPUTEDCODECONTEXT_H */

