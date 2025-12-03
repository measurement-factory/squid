#!/usr/bin/perl
#
## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Reads a space-separated list of directory names from STDIN.
# Writes a list of '|' separated absolute directory paths, located
# in the current directory except for the entries read from STDIN.

use strict;
use warnings;
use Cwd qw(abs_path);
use File::Spec;
use File::Basename;


# read the list of excluded directory names from STDIN into a hash
my %excluded;
my $inputLine = <STDIN>;
if (!$inputLine) {
    die "Cannot read directory names list from STDIN\n";
}

chomp($inputLine);
foreach my $dirName (split /\s+/, $inputLine) {
    $excluded{$dirName} = 1;
}

# Get the list of directories in the current working directory
my @allDirs;
opendir(my $dh, '.') or die "Cannot open current directory: $!";
while (my $entry = readdir($dh)) {
    next if $entry eq '.' || $entry eq '..';
    # Check if the entry is a directory
    if (-d $entry) {
        push @allDirs, $entry;
    }
}
closedir($dh);

# apply the filters
my @filteredDirs;
foreach my $relPath (@allDirs) {
    if ($relPath =~ /^\./) {
        next;
    }

    if (exists($excluded{$relPath})) {
        next;
    }
    
    my $absPath = abs_path($relPath);
    if (defined $absPath) {
        push @filteredDirs, "^$absPath/";
    }
}

print join("|", @filteredDirs);

