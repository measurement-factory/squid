/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Store.h"
#include "testStore.h"
#include "unitTestMain.h"

#include <limits>

CPPUNIT_TEST_SUITE_REGISTRATION( TestStore );

int
StoreControllerStub::callback()
{
    return 1;
}

StoreEntry*
StoreControllerStub::get(const cache_key*)
{
    return nullptr;
}

void
StoreControllerStub::get(String, void (*)(StoreEntry*, void*), void*)
{}

void
StoreControllerStub::init()
{}

uint64_t
StoreControllerStub::maxSize() const
{
    return 3;
}

uint64_t
StoreControllerStub::minSize() const
{
    return 1;
}

uint64_t
StoreControllerStub::currentSize() const
{
    return 2;
}

uint64_t
StoreControllerStub::currentCount() const
{
    return 2;
}

int64_t
StoreControllerStub::maxObjectSize() const
{
    return 1;
}

void
StoreControllerStub::getStats(StoreInfoStats &) const
{
}

void
StoreControllerStub::stat(StoreEntry &) const
{
    const_cast<StoreControllerStub *>(this)->statsCalled = true;
}

StoreSearch *
StoreControllerStub::search()
{
    return nullptr;
}

void
TestStore::testSetRoot()
{
    Store::Controller *aStore(new StoreControllerStub);
    Store::Init(aStore);

    CPPUNIT_ASSERT_EQUAL(&Store::Root(), aStore);
    Store::FreeMemory();
}

void
TestStore::testUnsetRoot()
{
    Store::Controller *aStore(new StoreControllerStub);
    Store::Controller *aStore2(new StoreControllerStub);
    Store::Init(aStore);
    Store::FreeMemory();
    Store::Init(aStore2);
    CPPUNIT_ASSERT_EQUAL(&Store::Root(),aStore2);
    Store::FreeMemory();
}

void
TestStore::testStats()
{
    StoreControllerStub *aStore(new StoreControllerStub);
    Store::Init(aStore);
    CPPUNIT_ASSERT_EQUAL(false, aStore->statsCalled);
    StoreEntry entry;
    Store::Stats(&entry);
    CPPUNIT_ASSERT_EQUAL(true, aStore->statsCalled);
    Store::FreeMemory();
}

void
TestStore::testMaxSize()
{
    Store::Controller *aStore(new StoreControllerStub);
    Store::Init(aStore);
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(3), aStore->maxSize());
    Store::FreeMemory();
}

