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

if (@ARGV != 1) {
    die "Usage: $0 <xunused-supp>\n";
}

my $xunusedSupp = $ARGV[0];
my $tmpDir = $ENV{TMPDIR} || "/tmp";

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

my %linesWithMatches;

while (<STDIN>) {
    chomp;
    my $line = $_;
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
        print "$line\n";
    }
}

# Apply suppressions, store the suppression statistics

my @notMatchedPatterns;

foreach my $pattern (@patterns) {
    my $matches = $suppStats{$pattern};
    my $count = scalar @$matches;

    if ($count > 0) {
        print STDERR "--- Suppression: $pattern (Matches: $count) ---\n";
        foreach my $line (@$matches) {
            print STDERR "    $line\n";
        }
        print STDERR "\n";
    } else {
        push @notMatchedPatterns, $pattern;
    }
}

my $unmatchedCount = @notMatchedPatterns;

if ($unmatchedCount > 0) {
    print STDERR "--- Suppressions not matched by xunused output: $unmatchedCount ---\n";
    foreach my $pattern (@notMatchedPatterns) {
        print STDERR "    $pattern\n";
    }
    print STDERR "\n";
}

foreach my $line (keys %linesWithMatches) {
    my $linePatterns = $linesWithMatches{$line};
    my $count = scalar @$linePatterns;
    my $printedHeader = 0;
    if ($count > 1) {
        if (!$printedHeader) {
            print STDERR "--- Lines matched by multiple suppressions ---\n";
            $printedHeader = 1;
        }
        print STDERR "    Line: $line\n";
        print STDERR "    Patterns ($count):\n";
        foreach my $pattern (@$linePatterns) {
            print STDERR "        $pattern\n";
        }
        print STDERR "\n";
    }
}

