#!/usr/bin/perl
use strict;
use warnings;

my $currentFunction = undef;
my %fileRangesUsed;
my %fileRangesUnused;

sub addRangeToFileUnused {
    my ($fileName, $newStart, $newEnd, $fileRanges) = @_;
    my $isUnused = ($fileRanges == \%fileRangesUnused);
    my $str = $isUnused ? "unused" : "used";
    print "'$fileName': adding ranges $newStart,$newEnd to $str\n";
    if ($newStart < 1 && $newStart > $newEnd) {
        die "FATAL: in $fileName: wrong range: $newStart > $newEnd\n";
    }
    if (exists $fileRanges->{$fileName}) {
        my $pairsRef = $fileRanges->{$fileName};
        foreach my $range (@$pairsRef) {
            my ($existStart, $existEnd) = @$range;

            if ($newStart == $existEnd && $newEnd == $existStart) {
                print "'$fileName': skipping duplicate $existStart,$existEnd range \n";
                return;
            }

            if ($isUnused) {
                if ($newStart <= $existEnd && $newEnd >= $existStart) {
                    die "FATAL: in $fileName: Range [$newStart, $newEnd] overlaps with [$existStart, $existEnd]\n";
                }
            }
        }
    }
    push @{$fileRanges->{$fileName}}, [$newStart, $newEnd];
}

my $inputFile = shift or die "Usage: $0 <input_file>\n";
open(my $ih, '<', $inputFile) or die "Could not open $inputFile: $!";

my $fileRanges = undef;
while (my $line = <$ih>) {
    print "Processing '$line'\n";
    if ($line =~ /^.+:\d+: warning: Function '(.+)' is unused$/) {
        $currentFunction = $1;
        $fileRanges = \%fileRangesUnused;
        next;
    }
    if ($line =~ /^.+:\d+: note: Function '(.+)' uses=\d+$/) {
        $currentFunction = $1;
        $fileRanges = \%fileRangesUsed;
        next;
    }

    if (defined $currentFunction && $line =~ /^([^:\s]+):(\d+): note: (defined|declared|comment starts) here$/) {

        my $file = $1;
        my $start = $2;
        my $type = $3;

        my $nextLine = <$ih>;
        if (!defined $nextLine) {
            die "FATAL: Unexpected EOF after $line\n";
        }

        my $expectedSuffix = undef;

        if ($type eq 'defined') {
            $expectedSuffix = 'definition ends here'
        } elsif ($type eq 'declared') {
            $expectedSuffix = 'declaration ends here';
        } else {
            ($type eq 'comment starts') or die "FATAL: Invalid message type: $type";
            $expectedSuffix = 'comment ends here';
        }

        if ($nextLine =~ /^([^:\s]+):(\d+): note: $expectedSuffix$/) {
            if ($file ne $1) {
               die "FATAL: file name mismatch in $line and $nextLine";
            }
            my $end = $2;

            defined($fileRanges) or die "Parse error in $start";
            addRangeToFileUnused($file, $start, $end, $fileRanges);
        } else {
            die "FATAL: Expected 'note: $expectedSuffix' after line $start,\n" .
                "but found: $nextLine";
        }
    } else {
        $currentFunction = undef;
        $fileRanges = undef;
    }
}

# apply removals
foreach my $file (sort keys %fileRangesUnused) {
    if (!-e $file) {
        die "FATAL: '$file' not found.\n";
    }

    open(my $fh, '<', $file) or die "ERROR: Could not open '$file': $!\n";
    my @content = <$fh>;
    close($fh);

    my $totalLines = scalar @content;
    my %linesToDelete;

    my $usedRanges = $fileRangesUsed{$file};
    my $overlapped = 0;

    foreach my $rangePair (@{$fileRangesUnused{$file}}) {
        my ($s, $e) = @$rangePair;

        if ($e > $totalLines) {
            die "FATAL: Range $s-$e is out of bounds for '$file'.\n";
        }

        if (defined $usedRanges) {
            foreach my $usedRange(@$usedRanges) {
                my ($us, $ue) = @$usedRange;
                if ($us == $s && $ue == $e) {
                    print "'$file': overriding same-line unused range with used range (functions defined by the same macro?) at $s,$e \n";
                    $s = 0;
                    $e = 0;
                    last;
                }
                if ($us <= $e && $ue >= $s) {
                    print "WARN: in $file: Unused range [$s, $e] overlaps with used range [$us, $ue]\n";
                    $overlapped = 1;
                }
            }
        }

        for (my $i = $s; $i <= $e; $i++) {
            $linesToDelete{$i} = 1;
        }
    }

    if ($overlapped) {
        print "Skipping $file due to operlapping errors\n";
        delete $fileRangesUnused{$file};
        next;
    }

    open(my $out, '>', $file) or die "ERROR: Cannot write to '$file': $!\n";

    my $emptyLines = undef;
    for (my $i = 0; $i < $totalLines; $i++) {
        chomp(my $line = $content[$i]);
        if ($line eq "") {
            if (defined $emptyLines) {
                $emptyLines .= $content[$i];
            } else {
                $emptyLines = $content[$i];
            }
            next;
        }

        if (defined $emptyLines) {
            if (!exists $linesToDelete{$i + 1}) {
                print $out $emptyLines;
            }
            $emptyLines = undef;
        }

        print $out $content[$i] unless exists $linesToDelete{$i + 1};
    }
    # write empty line leftovers
    if (defined $emptyLines) {
        print $out $emptyLines;
    }
    close($out);

    print "Processed '$file': " . (scalar keys %linesToDelete) . " lines removed.\n";
}

