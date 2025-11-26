#!/usr/bin/perl
#
## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Applies suppressions from xunused.supp to the log produced by xunused tool.

use strict;
use warnings;
use IO::Handle;

if (@ARGV != 2) {
    die "Usage: $0 <xunused-log> <xunused-supp>\n";
}

my $xunusedLog = $ARGV[0];
my $xunusedSupp = $ARGV[1];
my $tmpDir = $ENV{TMPDIR} || "/tmp";

my $xunusedSuppStatLog = "$tmpDir/test-ast-suppressed-stats.txt";

my %suppStats;
my @patterns;

open(my $xunusedSuppHandle, '<', $xunusedSupp) or die "Cannot open $xunusedSupp: $!";

# Read suppressions

while (my $line = <$xunusedSuppHandle>) {
    chomp $line;
    next if $line =~ /^\s*#/;
    next if $line =~ /^\s*$/;
    push @patterns, $line;
    $suppStats{$line} = [];
}

close($xunusedSuppHandle);

# Collect suppression statistics

open(my $xunusedLogHandle, '<', $xunusedLog) or die "Cannot open $xunusedLog: $!";

my %linesWithMatches;

while (my $line = <$xunusedLogHandle>) {
    $linesWithMatches{$line} = [];
    my $matched = 0;
    foreach my $pattern (@patterns) {
        if ($line =~ /$pattern/) {
            $matched++;
            push @{ $suppStats{$pattern} }, $line;
            push @{ $linesWithMatches{$line} }, $pattern;
        }
    }
    if ($matched == 0) {
        print $line;
    }
}

close($xunusedLogHandle);

# Apply suppressions, store the suppression statistics

open(my $statsHandle, '>', $xunusedSuppStatLog) or die "Cannot open $xunusedSuppStatLog for writing: $!";

my @notMatchedPatterns;

foreach my $pattern (@patterns) {
    my $matches = $suppStats{$pattern};
    my $count = scalar @$matches;

    if ($count > 0) {
        print $statsHandle "--- Suppression: $pattern (Matches: $count) ---\n";
        foreach my $line (@$matches) {
            print $statsHandle "    $line";
        }
        print $statsHandle "\n";
    } else {
        push @notMatchedPatterns, $pattern;
    }
}

my $unmatchedCount = @notMatchedPatterns;

if ($unmatchedCount > 0) {
    print $statsHandle "--- Suppressions not matched by xunused output: $unmatchedCount ---\n";
    foreach my $pattern (@notMatchedPatterns) {
        print $statsHandle "    $pattern\n";
    }
    print $statsHandle "\n";
}

foreach my $line (keys %linesWithMatches) {
    my $linePatterns = $linesWithMatches{$line};
    my $count = scalar @$linePatterns;
    my $printedHeader = 0;
    if ($count > 1) {
        if (!$printedHeader) {
            print $statsHandle "--- Lines matched by multiple suppressions ---\n";
            $printedHeader = 1;
        }
        print $statsHandle "    Line: $line";
        print $statsHandle "    Patterns ($count):\n";
        foreach my $pattern (@$linePatterns) {
            print $statsHandle "        $pattern\n";
        }
        print $statsHandle "\n";
    }
}

close($statsHandle);

