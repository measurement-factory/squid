/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "base/TextException.h"
#include "compat/cppunit.h"
#include "debug/Stream.h"
#include "unitTestMain.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#if !_SQUID_WINDOWS_

// A helper class that counts stderr lines,
// by redirecting file descriptor 2 (stderr) to a pipe,
// then reading the pipe and counting newlines.
class StderrCapture
{
public:
    StderrCapture() {
        assert(pipe(pipeFd) != -1);
        savedStderr = dup(STDERR_FILENO);
        dup2(pipeFd[1], STDERR_FILENO);
        close(pipeFd[1]); // stderr now owns this fd
    }

    ~StderrCapture() {
        restore();

        if (pipeFd[0] >= 0)
            close(pipeFd[0]);

        if (savedStderr >= 0)
            close(savedStderr);

    }

    int stopAndCountLines() {
        restore();

        int lines = 0;
        char buf[4096];

        ssize_t n;
        while ((n = read(pipeFd[0], buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < n; ++i)
                lines += (buf[i] == '\n');
        }

        return lines;
    }

private:
    void restore() {
        if (savedStderr >= 0) {
            fflush(stderr);
            dup2(savedStderr, STDERR_FILENO);
        }
    }

    int pipeFd[2] {-1, -1};
    int savedStderr {-1};
};

#endif /* _SQUID_WINDOWS_ */

class TestDebugs : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestDebugs);
    CPPUNIT_TEST(testAll);
    CPPUNIT_TEST_SUITE_END();

protected:

    void TestSimple();
    void TestOne(const int level, const int maxLevel);
    void TestMany(const int level, const int minThrowingLevel, const int maxThrowingLevel, const int maxLevel);
    void testAll();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestDebugs);

static const char *
ThrowAnException()
{
    throw TextException("Unexpected exception", Here());
    return "";
}

// Recursively calls itself via debugs() until level <= maxLevel and
// throws if level > maxLevel. 
static const char *
RecursiveDebugsSingleException(const int level, const int maxLevel)
{
    if (level > maxLevel)
        throw TextException("an exception", Here());

    debugs(1, DBG_IMPORTANT, RecursiveDebugsSingleException(level+1, maxLevel));
    return "single exception: after";
}

// Recursively calls itself via debugs() until level < maxLevel and then
// either throws if level is in the (minThrowingLevel, maxThrowingLevel] range
// or returns a string. 
static const char *
RecursiveDebugsMultipleExceptions(const int level, const int minThrowingLevel, const int maxThrowingLevel, const int maxLevel)
{
    assert(level <= maxLevel);
    assert(minThrowingLevel < maxThrowingLevel);
    assert(maxThrowingLevel < maxLevel);

    if (level == maxLevel)
        return "multiple exceptions: before";

    if (level > maxThrowingLevel) {
        debugs(1, DBG_IMPORTANT, RecursiveDebugsMultipleExceptions(level+1, minThrowingLevel, maxThrowingLevel, maxLevel));
        return "multiple exceptions: before";
    }

    if (level > minThrowingLevel) {
        debugs(1, DBG_IMPORTANT, RecursiveDebugsMultipleExceptions(level+1, minThrowingLevel, maxThrowingLevel, maxLevel));
        throw TextException("an exception", Here());
    }

    debugs(1, DBG_IMPORTANT, RecursiveDebugsMultipleExceptions(level+1, minThrowingLevel, maxThrowingLevel, maxLevel));
    return "multiple exceptions: after";
}

// check that a throwing debugs() does not break
// other debugs() that go before and after the call
void
TestDebugs::TestSimple() {
#if !_SQUID_WINDOWS_
    StderrCapture capture;
#endif
    try {
        debugs(1, DBG_IMPORTANT, "message before");
        debugs(1, DBG_IMPORTANT, ThrowAnException());
        debugs(1, DBG_IMPORTANT, "message after");
    } catch (...) {}
#if !_SQUID_WINDOWS_
    const auto count = capture.stopAndCountLines();
    CPPUNIT_ASSERT_EQUAL(2, count);
#endif
}

// check that if there are N nested debugs() messages stored in the Debug::Current list
// and the N+1 debugs() throws, these prevoius N messages are logged correctly
void
TestDebugs::TestOne(const int level, const int maxLevel) {
#if !_SQUID_WINDOWS_
    StderrCapture capture;
#endif
    try {
        debugs(1, DBG_IMPORTANT, RecursiveDebugsSingleException(level, maxLevel));
    } catch (...) {}
#if !_SQUID_WINDOWS_
    const auto count = capture.stopAndCountLines();
    CPPUNIT_ASSERT_EQUAL(maxLevel, count);
#endif
}

// This test stores N nested debugs() messages in the Debug::Current list,
// and then
// 1. completes K debugs() calls successfully
// 2. aborts L debugs() calls by throwing an exception
// 3. completes M debugs() calls successfully
// where N = K+L+M.
// The test checks that the number of logged messages is K+M.
void
TestDebugs::TestMany(const int level, const int minThrowingLevel, const int maxThrowingLevel, const int maxLevel)
{
#if !_SQUID_WINDOWS_
    StderrCapture capture;
#endif
    try {
        debugs(1, DBG_IMPORTANT, RecursiveDebugsMultipleExceptions(level, minThrowingLevel, maxThrowingLevel, maxLevel));
    } catch (...) {}
#if !_SQUID_WINDOWS_
    const auto count = capture.stopAndCountLines();
    const auto before = minThrowingLevel-level+1;
    const auto after = maxLevel-maxThrowingLevel;
    CPPUNIT_ASSERT_EQUAL(before+after, count);
#endif
}

void
TestDebugs::testAll() 
{
    Debug::Levels[0] = 1;
    Debug::Levels[1] = 1;
    Debug::ResetStderrLevel(1);

    TestSimple();

    TestOne(1, 0);
    TestOne(1, 10);

    TestMany(1, 10, 20, 30);
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

