#!/bin/bash
#
## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Finds unused functions using xunused tool.
# Must be run from the source root directory.

# Default-set and report used environment variables:
# * the root directory for storing test tools and test artifacts.
echo "TMPDIR=${TMPDIR:=${RUNNER_TEMP:-/tmp}}"

configureBinary=./configure
buildLog=${TMPDIR}/test-ast-build.log
xunusedLog=${TMPDIR}/test-ast-xunused.log

if [ ! -x $configureBinary ]
then
    echo "$0 must be run from the source root directory (where $configureBinary is)." >&2
    exit 1
fi

customCompileCommands=$1
defaultCompileCommands=compile_commands.json

if [ -n $customCompileCommands ]
then
    if [ ! -f $customCompileCommands ]
    then
        echo "$customCompileCommands file does not exist." >&2
        exit 1
    fi
fi

myConfigure() {

    # maximize the number of compiled source code files
    CONFIGURE_FLAGS="
        --enable-async-io
        --enable-auth
        --enable-auto-locale
        --enable-basic-auth-helpers
        --enable-cache-digests
        --enable-cachemgr-hostname
        --enable-debug-cbdata
        --enable-default-hostsfile=/etc/hosts
        --enable-delay-pools
        --enable-digest-auth-helpers
        --enable-disk-io
        --enable-esi
        --enable-eui
        --enable-external-acl-helpers
        --enable-follow-x-forwarded-for
        --enable-forw-via-db
        --enable-gnuregex
        --enable-htcp
        --enable-http-violations
        --enable-icap-client
        --enable-icmp
        --enable-ident-lookups
        --enable-ipv6
        --enable-kill-parent-hack
        --enable-linux-netfilter
        --enable-loadable-modules
        --enable-log-daemon-helpers
        --enable-mempools
        --enable-negotiate-auth-helpers
        --enable-ntlm-auth-helpers
        --enable-ntlm-fail-open
        --enable-referer-log
        --enable-removal-policies
        --enable-security-cert-generators
        --enable-security-cert-validators
        --enable-snmp
        --enable-ssl-crtd
        --enable-stacktraces
        --enable-storeid-rewrite-helpers
        --enable-storeio
        --enable-translation
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
        --enable-ecap
    "

    branch=`git rev-parse --abbrev-ref HEAD`
    commit=`git rev-parse --short HEAD`

    $configureBinary \
        CXX=clang++ \
        CC=clang \
        CXXFLAGS='-DUSE_POLL=1 -DUSE_SELECT=1' \
        $CONFIGURE_FLAGS \
        \
        --enable-build-info="$branch $commit for xunused" \
        --disable-strict-error-checking \
        --disable-optimizations
}

buildCompilationDatabase() {
    bear --version || exit $?

    make -k distclean || true
    ./bootstrap.sh
    myConfigure

    make clean

    bear --outfile $defaultCompileCommands -- make all check
}

# Before we run any heavy/long commands, ensure they have a chance to succeed.
# Version information is also useful for independently reproducing problems.
xunused --version || exit $?

compileCommands=$defaultCompileCommands

if [ -z $customCompileCommands ]
then
    buildCompilationDatabase > $buildLog 2>&1 || exit $?
else
    compileCommands=$customCompileCommands
fi

xunused $compileCommands > $xunusedLog 2>&1 || exit $?

unusedFunctionCount=`grep -c "is unused$" $xunusedLog`
echo "Unused functions: $unusedFunctionCount"
if [ "$unusedFunctionCount" -eq 0 ]
then
    exit 0
fi

exit 1

