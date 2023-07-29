/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLNOTE_H
#define SQUID_ACLNOTE_H

#include "acl/CharacterSetOption.h"
#include "acl/Data.h"
#include "acl/Strategy.h"
#include "Notes.h"

class HttpHeader;

namespace Acl {

/// common parent of several ACLs dealing with transaction annotations
class AnnotationStrategy: public ACLStrategy<NotePairs::Entry *>
{
public:
    AnnotationStrategy(): delimiters(CharacterSet(__FILE__, ",")) {}

    const Acl::Options &options() override;

    Acl::CharacterSetOptionValue delimiters; ///< annotation separators
};

} // namespace Acl

/// \ingroup ACLAPI
class ACLNoteStrategy: public Acl::AnnotationStrategy
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override { return true; }

private:
    bool matchHeaderEntries(ACLData<MatchType> *, const HttpHeader &) const;
    bool matchNotes(ACLData<MatchType> *, const NotePairs *) const;
};

#endif /* SQUID_ACLNOTE_H */

