#!/usr/bin/perl
#
## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Applies suppressions from a suppressions file to the log
# produced by xunused tool (read from STDIN).
# Prints not-suppressed lines with unused functions to STDOUT.
# Prints suppression statistics to STDERR.

use strict;
use warnings;
use IO::Handle;

my $tmpDir = $ENV{TMPDIR} || "/tmp";
my %suppStats;
my @patterns;
my %linesWithMatches;
my @notMatchedPatterns;

if (@ARGV != 1) {
    die "Usage: $0 <xunused-supp>\n";
} else {
    &main();
    exit 0;
}

sub readSuppressions {
    my $xunusedSupp = $ARGV[0];
    open(my $xunusedSuppHandle, '<', $xunusedSupp) or die "Cannot open $xunusedSupp: $!";
    while (my $line = <$xunusedSuppHandle>) {
        chomp $line;
        next if $line =~ /^\s*#/;
        next if $line =~ /^\s*$/;
        push @patterns, $line;
        $suppStats{$line} = [];
    }
    close($xunusedSuppHandle);
}

sub applySuppressions {
    while (<STDIN>) {
        chomp;
        my $line = $_;
        next if $line !~ /is unused$/;
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
            print "$line\n"; # not suppressed lines
        }
    }
}

sub printSuppressionStats {
    # for each pattern print a list of suppressed lines
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

    # print unmatched patterns
    if ($unmatchedCount > 0) {
        print STDERR "--- Suppressions not matched by xunused output: $unmatchedCount ---\n";
        foreach my $pattern (@notMatchedPatterns) {
            print STDERR "    $pattern\n";
        }
        print STDERR "\n";
    }

    # print each line with multiple matching patterns
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
}

sub main {
   &readSuppressions();
   &applySuppressions();
   &printSuppressionStats();
}

