#!/bin/sh
#
## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Finds unused functions using xunused tool.
# Must be run from the source root directory.
#
# Usage: test-ast.sh [filename]
# where
#   filename: compile_commands.json file to use instead of slowly building one
#             in the temporary directory
#
# Exit code zero means that no unused functions were found.

# Default-set and report used environment variables:
# * the root directory for storing test tools and test artifacts.
echo "TMPDIR=${TMPDIR:=${RUNNER_TEMP:-/tmp}}"

configureBinary=./configure
buildLog=${TMPDIR}/test-ast-build.log
xunusedLog=${TMPDIR}/test-ast-xunused.log
suppressionFilter=./test-suite/test-ast-supp-filter.pl
suppressions=./test-suite/xunused.supp
suppressedLog=${TMPDIR}/test-ast-suppressed.log
suppressedStatLog=${TMPDIR}/test-ast-suppressed-stats.log

customCompileCommands=$1
defaultCompileCommands=${TMPDIR}/compile_commands.json

myConfigure() {

    # Maximize the amount of compiled source code.
    # When selecting among mutually exclusive features, use the most popular one.
    # Disable slow-to-build features that do not increase compiled code amounts.

    local configureFlagsExceptions=""

    # Enabling translation slows build a lot but does not expose more compiled source code.
    configureFlagsExceptions="$configureFlagsExceptions --disable-translation"

    # Enabling compiler optimizations slows down the build but does not expose more compiled source code.
    configureFlagsExceptions="$configureFlagsExceptions --disable-optimizations"

    # in alphabetical order
    local configureFlags="
        $configureFlagsExceptions
        --enable-async-io
        --enable-auth
        --enable-auto-locale
        --enable-basic-auth-helpers
        --enable-cache-digests
        --enable-default-hostsfile=/etc/hosts
        --enable-delay-pools
        --enable-digest-auth-helpers
        --enable-disk-io
        --enable-ecap
        --enable-eui
        --enable-external-acl-helpers
        --enable-follow-x-forwarded-for
        --enable-forw-via-db
        --enable-htcp
        --enable-http-violations
        --enable-icap-client
        --enable-icmp
        --enable-ipv6
        --enable-linux-netfilter
        --enable-log-daemon-helpers
        --enable-mempools
        --enable-negotiate-auth-helpers
        --enable-ntlm-auth-helpers
        --enable-ntlm-fail-open
        --enable-referer-log
        --enable-removal-policies
        --enable-security-cert-generators
        --enable-security-cert-validators
        --enable-shared
        --enable-snmp
        --enable-ssl-crtd
        --enable-stacktraces
        --enable-storeid-rewrite-helpers
        --enable-storeio
        --enable-unlinkd
        --enable-url-rewrite-helpers
        --enable-useragent-log
        --enable-vary
        --enable-wccp
        --enable-wccpv2
        --enable-x-accelerator-vary
        --enable-xmalloc-statistics
        --enable-zph-qos
        --with-aio
        --with-dl
        --with-dns-cname
        --with-gnu-ld
        --with-ipv6-split-stack
        --with-large-files
        --with-openssl
        --with-pic
        --with-pthreads
        --with-valgrind-debug
    "

    local branch=`git rev-parse --abbrev-ref HEAD`
    local commit=`git rev-parse --short HEAD`

    $configureBinary \
        CXX=clang++ \
        CC=clang \
        CXXFLAGS='-DUSE_POLL=1 -DUSE_SELECT=1' \
        $configureFlags \
        \
        --enable-build-info="$branch $commit for xunused" \
        --disable-strict-error-checking
}

buildCompilationDatabase() {
    bear --version || return

    make -k distclean > /dev/null 2>&1
    ./bootstrap.sh || return
    myConfigure || return

    make clean

    bear --output $defaultCompileCommands -- make all check
}

main() {
    # Before we run any heavy/long commands, ensure they have a chance to succeed.
    # Version information is also useful for independently reproducing problems.
    xunused --version || return

    if [ ! -x $configureBinary ]
    then
        echo "$0 must be run from the source root directory (where $configureBinary is)." >&2
        return 1
    fi

    local compileCommands=$defaultCompileCommands
    if [ -n "$customCompileCommands" ]
    then
        compileCommands=$customCompileCommands
        echo "Reusing a compilation database in $compileCommands"
    else
        echo "Slowly building a new compilation database in $compileCommands; see $buildLog"
        buildCompilationDatabase > $buildLog 2>&1 || return
    fi

    # This check is important because xunused appears to ignore a missing
    # compilation database file in many cases, processing whatever source
    # files it can find starting from the current directory instead!
    if [ ! -f "$compileCommands" ]
    then
        echo "Missing compilations database file: $compileCommands" >&2
        return 1
    fi

    xunused $compileCommands > $xunusedLog 2>&1 || return

    $suppressionFilter $suppressions <$xunusedLog 1>$suppressedLog 2>$suppressedStatLog || return

    local unusedFunctionCount=`grep -c "is unused$" $suppressedLog`
    echo "Unused functions: $unusedFunctionCount"
    if [ "$unusedFunctionCount" -eq 0 ]
    then
        return 0
    fi
    return 1
}

main
exit $?
