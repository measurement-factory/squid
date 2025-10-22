#!/bin/bash
#
## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Should be run from the source root directory.
# The 'xunused' utility should be placed into the source root directory. 

log=/tmp/test-ast.log

configureBinary=./configure 
xunusedBinary=./xunused
xunusedResult=./xunused_result.txt

if [ ! -x $configureBinary ]
then
    echo `basename "$0"`": Must be run in the root directory"
    exit 1
fi

if [ ! -x $xunusedBinary ]
then
    echo "Could not find xunused in the root directory"
    exit 1
fi

customCompileCommands=$1
defaultCompileCommands=compile_commands.json
compileCommands=./${defaultCompileCommands}

if test -n "$customCompileCommands"
then
    compileCommands=$customCompileCommands
fi

bearCompileOption="--outfile ${compileCommands}"

configure() {

    CONFIGURE_FLAGS_FOR_CLANG_TIDY="
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
        CXXFLAGS='-Wno-error -DUSE_POLL=1 -DUSE_SELECT=1' \
        $CONFIGURE_FLAGS_FOR_CLANG_TIDY \
        \
        --enable-build-info="$branch $commit" \
        --disable-strict-error-checking \
        --disable-optimizations
}

rm -i $log || true
rm -i $compileCommands || true
rm -i $xunusedResult || true

make -k distclean >> $log || true
./bootstrap.sh >> $log
configure >> $log

make clean >> $log

bear --append $bearCompileOption -- make all check >> $log

$xunusedBinary $compileCommands > $xunusedResult 2>&1

unusedLines=`grep "is unused$" $xunusedResult | wc -l`

echo "Unused functions: ${unusedLines}" >> $log 

if [ "$unusedLines" -eq 0 ]
then
   exit 0 
fi

exit 1

