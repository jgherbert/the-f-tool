#!/usr/bin/perl

# ip2bin.pl - Convert IPs/masks to something more useful for searching for subnet matches
#
# John Herbert, 2013-2014
# 
# We'll take the IP and mask, and create decimal ranges that we can compare against

use strict;

my $progName = 'ip2bin.pl';
my $progVer = '1.1.1 July 8, 2014';

# v1.1.0 begins supporting IPv6, probably quite badly.

# Need to know what host we're running on so we can correctly identify the data
# we're supposed to convert - it will have a matching identifier, e.g. ATL.

use Sys::Hostname;
my $sysHost = hostname;
$sysHost = (split(/\./,$sysHost))[0] if ($sysHost =~ /\./); # Just hostname please
my $dataSource = uc(substr($sysHost,0,3)) || "UNK";

# Set up input/output files
my $dataDir = '/data/fdb';
my $ipdata = $dataDir.'/'.$dataSource.'.ipdata.raw';
my $dbfile = $dataDir.'/'.$dataSource.'.ipbinary.db';

# Process local data file
processFile($ipdata,$dbfile);

# Fat lady sings
exit(0);


sub processFile {
	# Read raw IP file, and spew out results in pseudo-binary format
	my $ipdata = $_[0]; # input file (IP raw)
	my $dbfile = $_[1]; # output file (IP binary)

	# Test opening output file
	open(DB,">".$dbfile.'.tmp') || die("Can't write to file. $!\n");

	# Print conversion information to the data file for tracking
	print DB "## Conversion: $progName, v$progVer ($sysHost)\n";

	# Data separator
	my $sep = '&&'; # use && as a value separator

	open(IP,$ipdata) || die("Can't open IP data file $ipdata. $!\n");
	while (my $line = <IP>) {
		# Handle comment lines first
		if ($line =~ /^##/) {
			print DB $line;
			next;
		}

		my ($ip, $prefix, $value, $ver, $result, $binprefix);
		chomp($line);

        # Check IP version, if stated
        $line =~ /^v([46]):/;
        $ver = $1;

        # Strip IP version out, if it's there
        $line =~ s/^v([46])://;

        if (! $ver) {
            # In case it's old data without a version, look for a : in the first (IP) element of the line
            my @bits = split(/ /,$line);
            if ($bits[0] =~ /:/) {
                $ver = 6;
            }
        }

        if ($ver == 6) {
            # Process as IPv6
            $line =~ m!^([0-9a-f:]+)/(\d+)\s+(.*)$!;
            $ip = $1;
            $ip = lc($ip);
            $prefix = $2;
            $value = $3;
            #print STDERR "Processing $ip/$prefix as V6\n";

            # Mask sanity checks are done in the IP conversion code. Just because.
            my $binip = ipv62bin($ip.'/'.$prefix);
            #print STDERR "ProcessIP=$binip\n";
            $binprefix = '1' x $prefix. '0' x (128 - $prefix);
            #print STDERR "BinPrefix=$binprefix\n";

            if ($binip =~ /^Error:/) {
                die("!! Encountered error processing $ip/$prefix in $ipdata;\n$binip\n");
            }

            # Otherwise, do a binary AND on them just like we do for IPv4
            $result = 'v6' . $sep . ($binip & $binprefix);
        }
        else {
            # Process as IPv4
            # We'll process as v4 by default (also allows blank prefix for legacy support, yay)
            $line =~ m!^(\d+\.\d+\.\d+\.\d+)/(\d+)\s+(.*)$!;
            $ip = $1;
            $prefix = $2;
            $value = $3;

            # Get binary equivalents of the IP and prefix length
            my $binip   = ip2bin($ip);
            $binprefix = '1' x $prefix . '0' x  (32 - $prefix);

            # Now do a binary AND on them 
            $result = 'v4' . $sep . ($binip & $binprefix);
        }

		# So then, what we need to do is to store that with the mask length, the original data and a hostname etc
        # Ain't that purty:
		print DB "$result$sep$binprefix$sep$ip$sep$prefix$sep$value\n";
	}

	close(IP);
	close(DB);

	# They should now all be stored. We should rename the db file, right?

	if (-e $dbfile.'.old') {
		unlink($dbfile.'.old');
	}
	if (-e $dbfile) {
		rename ($dbfile, $dbfile.'.old');
	}
	rename ($dbfile.'.tmp', $dbfile);
} # end sub processFile

sub ip2bin {
    my $ip = $_[0];
    return     join("",  map substr(unpack("B32",pack("N",$_)),-8), split(/\./,$ip));
}

sub dec2bin {
    my $str = unpack("B32", pack("N", shift));
    #$str =~ s/^0+(?=\d)//;   # otherwise you'll get leading zeros
    return $str;
}

sub ipv62bin {
    # Take IP/mask in and expand all missing zeroes so we can then create 
    # a true binary representation of the 128-bit IP address
    my $ipadd = $_[0];
    my $host; my $mask;

    #print STDERR "Converting $ipadd.\n";

    ($host,$mask) = split(/\//,$ipadd,2);

    # Sanity checks
    if ($ipadd !~ /\//) {
        return "Error: No subnet mask defined.";
    }
    if (($mask < 0) || ($mask > 128)) {
        return "Error: Rejecting invalid IPv6 address mask: '$mask'";
    }
    if ($host !~ /:/) {
        return "Error: Rejecting invalid IPv6 address: '$host'";
    }

    # Prefix/suffix a missing 0, as it makes the :: processing work properly
    $host =~ s/:$/:0/;
    $host =~ s/^:/0:/;

    # Otherwise with any luck we have valid addresses to work with
    #print STDERR "Debug: Add = $host, Mask = $mask\n";
    # Break up the IP address into elements
    my @elements;
    @elements = split(/:/,$host);

    # Sanity check number of elements; should not exceed eight!
    if ($#elements > 7) {
        return "Error: Host '$host' appears to have too many elements ($#elements)!";
    }

    # First check for any parts that need leading zeroes
    my $doublecolon = 0;
    foreach my $element (@elements) {
        if (length($element) > 4) {
            # We have an invalid element
            return "Error: Element '$element' is invalid (too long).";
        }
        if ($element eq '') {
            # Must be double colon; need to keep this blank for now
            $doublecolon++;
            next;
        }
        $element = '0' x (4 - length($element)) . $element;
    }

    # Check for two :: - shouldn't be possible, but still...
    if ($doublecolon > 1) {
           return "Error: Host '$host' appears to have two :: in it!";
    }

    # Fix any missing elements
    if ($#elements < 7) {
        # There should be 8 elements, so we can replace the missing element(s) 
        my $missing = (8 - $#elements); # Mathematically incorrect, but it works to add in the correct number

        foreach my $element (@elements) {
            if ($element eq '') {
                # Must be double colon; replace it!
                $element = '0000' x $missing;
            }
        }
    }

    # Create a mask in binary-style format
    #print STDERR "Packing ".join('',@elements)."\n";
    return unpack('B128',pack('H32',join('',@elements)));
}


