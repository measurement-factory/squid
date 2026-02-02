#!/usr/bin/perl
use strict;
use warnings;

my $currentUnusedFunction = undef;
my %fileRanges;

sub addRangeToFile {
    my ($fileName, $newStart, $newEnd) = @_;
    if ($newStart < 1 && $newStart > $newEnd) {
        die "FATAL: in $fileName: wrong range: $newStart > $newEnd\n";
    }
    if (exists $fileRanges{$fileName}) {
        foreach my $range (@{$fileRanges{$fileName}}) {
            my ($existStart, $existEnd) = @$range;
            
            if ($newStart <= $existEnd && $newEnd >= $existStart) {
                die "FATAL: in $fileName: Range [$newStart, $newEnd] overlaps with [$existStart, $existEnd]\n";
            }
        }
    }
    push @{$fileRanges{$fileName}}, [$newStart, $newEnd];
}

my $inputFile = shift or die "Usage: $0 <input_file>\n";
open(my $ih, '<', $inputFile) or die "Could not open $inputFile: $!";

while (my $line = <$ih>) {
    print "Processing '$line'\n";
    if ($line =~ /^.+:\d+: warning: Function '(\w+)' is unused$/) {
        $currentUnusedFunction = $1;
        next;
    }

    if (defined $currentUnusedFunction && $line =~ /^([^:\s]+):(\d+): note: (defined|declared) here$/) {
        
        my $file = $1;
        my $start = $2;
        my $type = $3;

        my $nextLine = <$ih>;
        if (!defined $nextLine) {
            die "FATAL: Unexpected EOF after $line\n";
        }

        my $expectedSuffix = ($type eq 'defined') 
                            ? 'definition ends here' 
                            : 'declaration ends here';

        if ($nextLine =~ /^([^:\s]+):(\d+): note: $expectedSuffix$/) {
            if ($file ne $1) {
               die "FATAL: file name mismatch in $line and $nextLine";
            }
            my $end = $2;
            
            addRangeToFile($file, $start, $end);
        } else {
            die "FATAL: Expected 'note: $expectedSuffix' after line $start,\n" .
                "but found: $nextLine";
        }
    } else {
        $currentUnusedFunction = undef;
    }
}

# apply removals
foreach my $file (sort keys %fileRanges) {
    if (!-e $file) {
        die "FATAL: '$file' not found.\n";
    }

    open(my $fh, '<', $file) or die "ERROR: Could not open '$file': $!\n";
    my @content = <$fh>;
    close($fh);
    
    my $totalLines = scalar @content;
    my %linesToDelete;

    foreach my $rangePair (@{$fileRanges{$file}}) {
        my ($s, $e) = @$rangePair;

        if ($e > $totalLines) {
            die "FATAL: Range $s-$e is out of bounds for '$file'.\n";
        }

        for (my $i = $s; $i <= $e; $i++) {
            $linesToDelete{$i} = 1;
        }
    }

    open(my $out, '>', $file) or die "ERROR: Cannot write to '$file': $!\n";

    for (my $i = 0; $i < $totalLines; $i++) {
        print $out $content[$i] unless exists $linesToDelete{$i + 1};
    }
    close($out);
    
    print "Processed '$file': " . (scalar keys %linesToDelete) . " lines removed.\n";
}

