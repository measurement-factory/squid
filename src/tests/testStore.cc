/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Store.h"
#include "store/SwapMeta.h"
#include "testStore.h"
#include "unitTestMain.h"

#include <limits>

CPPUNIT_TEST_SUITE_REGISTRATION( TestStore );

namespace Store {

/// check rawType that may be ignored
static void
checkIgnorableSwapMetaRawType(const RawSwapMetaType rawType)
{
    if (IgnoredSwapMetaType(rawType)) {
        // an ignored raw type is either deprecated or reserved
        CPPUNIT_ASSERT(DeprecatedSwapMetaType(rawType) || ReservedSwapMetaType(rawType));
        CPPUNIT_ASSERT(!(DeprecatedSwapMetaType(rawType) && ReservedSwapMetaType(rawType)));
    } else {
        // all other raw types are neither deprecated nor reserved
        CPPUNIT_ASSERT(!DeprecatedSwapMetaType(rawType) && !ReservedSwapMetaType(rawType));
    }
}

/// check a raw swap meta field type below SwapMetaType range or STORE_META_VOID
static void
checkTooSmallSwapMetaRawType(const RawSwapMetaType rawType)
{
    // RawSwapMetaTypeBottom and smaller values are unrelated to any named
    // SwapMetaDataType values, including past, current, and future ones
    CPPUNIT_ASSERT(!HonoredSwapMetaType(rawType)); // current
    CPPUNIT_ASSERT(!IgnoredSwapMetaType(rawType)); // past and future
    CPPUNIT_ASSERT(!DeprecatedSwapMetaType(rawType)); // past
    CPPUNIT_ASSERT(!ReservedSwapMetaType(rawType)); // future
}

/// check a raw swap meta field type within SwapMetaType range, excluding STORE_META_VOID
static void
checkKnownSwapMetaRawType(const RawSwapMetaType rawType)
{
    // an in-range rawType other than STORE_META_VOID is either honored or ignored
    CPPUNIT_ASSERT(HonoredSwapMetaType(rawType) || IgnoredSwapMetaType(rawType));
    CPPUNIT_ASSERT(!(HonoredSwapMetaType(rawType) && IgnoredSwapMetaType(rawType)));
    checkIgnorableSwapMetaRawType(rawType);
}

/// check a raw swap meta field type exceeding RawSwapMetaTypeTop()
static void
checkTooBigSwapMetaRawType(const RawSwapMetaType rawType)
{
    // values beyond RawSwapMetaTypeTop() cannot be honored but may be ignored
    CPPUNIT_ASSERT(!HonoredSwapMetaType(rawType));
    checkIgnorableSwapMetaRawType(rawType);
}

/// check a given raw swap meta field type
static void
checkSwapMetaRawType(const RawSwapMetaType rawType)
{
    if (rawType <= RawSwapMetaTypeBottom)
        checkTooSmallSwapMetaRawType(rawType);
    else if (rawType > RawSwapMetaTypeTop())
        checkTooBigSwapMetaRawType(rawType);
    else
        checkKnownSwapMetaRawType(rawType);
}

} // namespace Store

void
TestStore::testSwapMetaTypeClassification()
{
    using limits = std::numeric_limits<Store::RawSwapMetaType>;
    for (auto rawType = limits::min(); true; ++rawType) {

        Store::checkSwapMetaRawType(rawType);

        if (rawType == limits::max())
            break;
    }

    // Store::RawSwapMetaTypeTop() is documented as an honored type value
    CPPUNIT_ASSERT(Store::HonoredSwapMetaType(Store::RawSwapMetaTypeTop()));
}

/// customizes our test setup
class MyTestProgram: public TestProgram
{
public:
    /* TestProgram API */
    void startup() override { Mem::Init(); }
};

int
main(int argc, char *argv[])
{
    return MyTestProgram().run(argc, argv);
}

