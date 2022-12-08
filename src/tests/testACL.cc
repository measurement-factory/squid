/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "acl/SourceIp.h"
#include "anyp/forward.h"
#include "anyp/PortCfg.h"
#include "ConfigParser.h"
#include "SquidConfig.h"
#include "tests/testACL.h"
#include "unitTestMain.h"

#include <array>

CPPUNIT_TEST_SUITE_REGISTRATION( testACL );

AnyP::PortCfgPointer HttpPortList;

extern ConfigParser LegacyParser;

void
testACL::setUp()
{
    CPPUNIT_NS::TestFixture::setUp();
    Acl::RegisterMaker("src", [](Acl::TypeName)->ACL* { return new ACLSourceIP; });
}

void
testACL::testMissingParametersSuccess()
{
    {
        const std::array <const char *, 2> lines = {
            "test src --missing-parameter-action=ignore",
            "test src --missing-parameter-action=warn"
        };
        auto &global = Config.rejectAclsWithEmptyParameterList;
        for (global = -1; global <= 1; ++global) {
            for (auto line: lines) {
                ConfigParser::SetCfgLine(line);
                ACL::ParseAclLine(LegacyParser, &Config.aclList);
                auto sourceAcl = dynamic_cast<ACLSourceIP *>(Config.aclList);
                CPPUNIT_ASSERT(sourceAcl);
                aclDestroyAcls(&Config.aclList);
                Config.aclList = nullptr;
            }
        }
    }

    {
        Config.rejectAclsWithEmptyParameterList = 0; // ignore
        ConfigParser::SetCfgLine("test src --missing-parameter-action=err 127.0.0.1");
        ACL::ParseAclLine(LegacyParser, &Config.aclList);
        auto sourceAcl = dynamic_cast<ACLSourceIP *>(Config.aclList);
        CPPUNIT_ASSERT(sourceAcl);

        // should not be affected by the first line and obey the global setting
        ConfigParser::SetCfgLine("test src");
        ACL::ParseAclLine(LegacyParser, &Config.aclList);
        sourceAcl = dynamic_cast<ACLSourceIP *>(Config.aclList);
        CPPUNIT_ASSERT(sourceAcl);
        aclDestroyAcls(&Config.aclList);
        Config.aclList = nullptr;
    }
}

void
testACL::testMissingParametersAbort()
{
    {
        auto &global = Config.rejectAclsWithEmptyParameterList;
        for (global = -1; global <= 1; ++global) {
            try {
                ConfigParser::SetCfgLine("test src --missing-parameter-action=err");
                ACL::ParseAclLine(LegacyParser, &Config.aclList);
                CPPUNIT_ASSERT_MESSAGE("expects a configuration error", false);
            } catch (const Configuration::MissingTokenException &) {
                // success
                aclDestroyAcls(&Config.aclList);
                Config.aclList = nullptr;
            }
        }
    }

    try {
        Config.rejectAclsWithEmptyParameterList = 1; // err
        ConfigParser::SetCfgLine("test src --missing-parameter-action=ignore");
        ACL::ParseAclLine(LegacyParser, &Config.aclList);
        ConfigParser::SetCfgLine("test src");
        // should not be affected by the first line and obey the global setting
        ACL::ParseAclLine(LegacyParser, &Config.aclList);
        CPPUNIT_ASSERT_MESSAGE("expects a configuration error", false);
    } catch (const Configuration::MissingTokenException &) {
        // success
        aclDestroyAcls(&Config.aclList);
        Config.aclList = nullptr;
    }
}

