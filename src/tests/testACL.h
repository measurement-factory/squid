/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_ACL_H
#define SQUID_SRC_TEST_ACL_H

#include "compat/cppunit.h"

class testACL: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testACL );
    CPPUNIT_TEST( testMissingParametersSuccess );
    CPPUNIT_TEST( testMissingParametersAbort );
    CPPUNIT_TEST_SUITE_END();

public:
    virtual void setUp() override;

protected:
    /* --missing-parameter-action option tests */
    void testMissingParametersSuccess();
    void testMissingParametersAbort();
};

#endif // SQUID_SRC_TEST_ACL_H

