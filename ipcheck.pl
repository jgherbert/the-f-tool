#!/usr/bin/perl
#
# ipcheck.pl - (C) John Herbert, September 2013 - December 2014
#
# See which IP database entries match the IP given on the command line
# 

my $progName = "f (ipcheck.pl)";
my $progVer = '1.2.4 - Aug 4, 2014';
my $progAuthor = 'John Herbert';
my $dataGenerator = 'ipgrabber.pl';
my $progDataSource = 'UNK';
my $latestbug = 'Nobody';

use strict;
use DB_File;
use Fcntl;
use Getopt::Std;

my $sep = '&&'; # data field separator

# v1.2.0 started to support ipv6. At least, it tried to.

# Need to know what host we're running on so we can correctly identify the data.
# Grab the 1st 3 chars of the hostname to identify the location where this is 
# being run. 

use Sys::Hostname;
my $sysHost = hostname;
$sysHost = (split(/\./,$sysHost))[0] if ($sysHost =~ /\./); # Just hostname please
my $dataSource = uc(substr($sysHost,0,3)) || "UNK";

# Data file location
my $dataDir = '/data/fdb';
my $dbExtension = '.ipbinary.db';


# Check ARGV options
my %o;
getopts('elfgtvmzdx:',\%o);
unless (@ARGV || grep { $_ }  @o{qw(t s v d l)}) {
    die <<EOH;

usage: f [-e] [-f] [-t] [-v] ipaddress [ipaddress2] .. [ipaddressN]

-e : show exact matches only (default shows subnet matches too)
-f : show firewall address book entries (default suppresses)
-t : show 10.0.0.0/8 firewall entries too. Implies -f.
-d : include date that source data was last modified
-v : show program version and data file information then quit
-m : minimal; returns only <hostname> or <unknown>. Implies -e
-z : minimal output designed for srxalyzer.pl use. Implies -e, -m
-g : minimal: first match of any kind. Excludes Subnet. Implies -e
-x : override standard data file

EOH
}

if ($o{'v'}) {
	displayInfo();
	exit(0);
}


# Humanize the m (minimal output) option
$o{'m'} = 1 if ($o{'z'}); # Set m if z set
my $minimal = ($o{'m'}) ? 1 : 0;
my $not_minimal = ($o{'m'}) ? 0 : 1;
$o{'e'} = 1 if $o{'m'}; # minimal implies exact match
if ($o{'g'}) {
       # Want minimal style but not exact match
       # And we'll do some other magic too, to identify exact versus non (like the *)
       $minimal = 1;
       $not_minimal = 0;
}

$o{'f'} = 0 if $o{'m'}; # can't check FW when exact matching
$o{'t'} = 0 if $o{'m'}; # Can't check 10/8 when exact matching

$o{'f'} = 1 if ($o{'t'}); # turn on firewall entries if -t option chosen

my $srxalyzer = $o{'z'} ? 1 : 0; # set human name for the option
$o{'d'} = 1 if ($o{'l'});
my $showmtime = $o{'d'} ? 1 : 0; # set human name for the option for last modifiation times

my $dbfile = $o{'z'}; # For future use (currently will do nothing... muhahaha)

# Load database into array (lord help us)
my @subnets;
my @masks;
my @origips;
my @prefixes;
my @values;
my @versions;


# Check data directory for files ending in $dbExtension, and read them all in
my $count; # Count how many lines were checked
my %dataTimeStamp; # Store timestamp. Key will be the data center

# Run through the dataDar
opendir(DIR,$dataDir);
foreach my $file (readdir(DIR)) {
	next if ($file !~ /$dbExtension$/); # only read the ipbinary.db files
	# Extract the first 3 chars of the file, as that's the original data source
	my $site = substr($file,0,3);
	open (IN,$dataDir.'/'.$file) || die ("Can't read database file for $site. $!\n");
	while (my $line = <IN>) {
		chomp($line);
		# Deal with header lines (##)
		if ($line =~ /^##/) {
			# Grab timestamp
			if ($line =~ /Timestamp: (.*)$/) {
				$dataTimeStamp{$site} = $1;
			}
			# Otherwise move on and ignore the line
			next;
		}
		#Otherwise, assume it's a data line:
        my ($version,$subnet,$mask,$origip,$prefix,$value);
        if ($line =~ /^v/) {
            ($version,$subnet,$mask,$origip,$prefix,$value) = split(/$sep/,$line,6);
        }
        else {
            ($subnet,$mask,$origip,$prefix,$value) = split(/$sep/,$line,5);
            $version = 'v4';
        }
        push (@versions,$version);
		push (@subnets,$subnet);
		push (@masks,$mask);
		push (@origips,$origip);
		push (@prefixes,$prefix);
		push (@values,$value);
		$count++;
	}
	close (IN);
	# Rinse and repeat for other files in the directory
} # end foreach

# Process arguments

if ($not_minimal) {
	print STDOUT <<END;
----------------------------------------------------------
ipcheck (f) - Find IPs / Subnets / Address Book Entries
  * = Exact IP match
----------------------------------------------------------
END
	print STDOUT "\n" if ($o{'e'} || $o{'t'});
	print STDOUT "** Option selected: Exact matches only **\n" if ($o{'e'});
	print STDOUT "** Option selected: Include 10.0.0.0/8 FW entries **\n" if ($o{'t'});
	print STDOUT "** Option selected: Use data file $o{'x'} **\n" if ($o{'x'});
	print STDOUT "** Option selected: Include last modification date of source data **\n" if ($o{'d'});
}

foreach my $ip (@ARGV) {
	if ($minimal) {
		my $match = match($ip);	
		if ($match ne "unknown") {
            # Note if it was an exact match
            my $exactmatch = '';
            $exactmatch = '*' if ($match =~ /\*/);

            # Split string to remove IP etc
            $match =~ s/^\s//g; # remove leading spaces
            (undef,$match) = split(/\s+/,$match,2);

            # Now process to remove junk
            if ($o{'g'}) {
                # First match only, minimal output
                $match =~ /\s+([\w\d\-\_\.\\\/]+)\s/;
                $match = $1;
                $match = $exactmatch.$match; # note if exact
            }
            else {
                $match =~ /\*\s+([\w\d\-\_\.\\\/]+)\s/;
                $match = $1;
            }
		}
		if ($srxalyzer) {
			print STDOUT $ip . '==' . $match;
		}
		else {
			print STDOUT $match;
		}
	}
	else {
		print STDOUT "\n$ip:" . match($ip) . "\n";
	}
}

# Log for fun
loguse();

print STDOUT "\nChecked $count records.\n\n" if ($not_minimal);

exit(0);

sub match {
	my $ip = shift;
	my @result; # Store other matches here
	my @exact; #Store exact matches so we can list those first
	my @firewall; # Store firewall matches and display those last
	my @firewalltop; # Store firewall exact matches and display those last
    my $queryversion;

    # I _really_ must sanitize $ip at some point...
    #
    if ($ip =~ /:/) {
        $queryversion = 'v6';
        #print STDERR "Checking address as v6.\n";
    }
    else {
        $queryversion = 'v4';
    }

	# Turn IP from command line into binary string so we can 
	# manipulate with binary nonsense
	my $ipbin; 

    #print STDERR "Checking query ip $ip\n";
    # Convert the query IP to binary
    if ($queryversion eq 'v6') {

        # Check no bad characters in there
        $ip = lc($ip); # make sure all chars are lower case, as that's our search basis too
        if ($ip =~ /[^0-9a-f:]/) {
            print STDERR "\n\n!! Queried address $ip contains invalid characters!\n\n$ipbin\n";
            exit(1);
        }

        $ipbin = ipv62bin($ip.'/128');
        #print "Received search string $ipbin.\n";
        if ($ipbin =~ /^Error:/) {
            print STDERR "\n\n!! Queried address $ip is invalid!\n\n$ipbin\n";
            exit(1);
        }
    }
    else {
        $ipbin = ip2bin($ip);
    }

	for (my $x=0; $x<=$#subnets; $x++) {
		# Compare the stored binary subnet against ($mask & $ipbin)

        # Only check ipbinary data against matching IP versions, right?
        next if ($versions[$x] ne $queryversion);
        #print STDERR "Proceeding and checking a $queryversion IP!\n";

        #print STDERR "Subnets: $subnets[$x]\n";
        #print STDERR "Compare: " . ($masks[$x] & $ipbin) ."\n";

		if ($subnets[$x] eq ($masks[$x] & $ipbin)) {
            #print STDERR "I matched $subnets[$x] with $masks[$x] and $ipbin\n";
            # Remove date by default, unless -l (showmtime) option specified
            if (! $showmtime) {
                # Strip date, e,g, "  [[2014-08-07]]"
                $values[$x] =~ s/\s+\[\[\d\d\d\d-\d\d-\d\d\]\]$//;
            }

			# Is if a fw address book entry?
			if ($values[$x] =~ /\{FW\}/) {
				# Yes it's a firewall thingy
				# Check if it contains 10.0.0.0/8 - because unless -t is selected, we shouldn't even both
				my $tempip = $origips[$x].'/'.$prefixes[$x];
				if ((!($o{'t'})) && ($tempip eq '10.0.0.0/8')) {
					next;
				}
				else {
					# process if -t option was not selected and it is not 10.0.0.0/8
					# Is it an exact match?
					if ($ip eq $origips[$x]) {
						push(@firewalltop,sprintf("  %18s* %s",$origips[$x].'/'.$prefixes[$x],$values[$x]));
					}
					else {
						push(@firewall,sprintf("  %18s  %s",$origips[$x].'/'.$prefixes[$x],$values[$x]));
					}
				}
			}
			else {
				# Is it an exact match?
                if ($queryversion eq 'v6') {
                    # Determine exact match for v6...trickier given shortened formats in use. Need to normalize
                    # in order to evaluate (oh joy)
                    # The search IP (/128) is $ipbin
                    # Original IP is stored in $origips[$x]
                    my $origbin = ipv62bin($origips[$x].'/128'); # Convert to standard binary format
                    if ($origbin eq $ipbin) {
                        # Yes it is!
                        push(@exact,sprintf("  %18s* %s",$origips[$x].'/'.$prefixes[$x],$values[$x]));
                    }
                    else {
                        # All non-exact matches get put on the stack
                        push(@result,sprintf("  %18s  %s",$origips[$x].'/'.$prefixes[$x],$values[$x]));
                    }
                }
                else {
                    if ($ip eq $origips[$x]) {
                        # Yes it is!
                        push(@exact,sprintf("  %18s* %s",$origips[$x].'/'.$prefixes[$x],$values[$x]));
                    }
                    else {
                        # All non-exact matches get put on the stack
                        push(@result,sprintf("  %18s  %s",$origips[$x].'/'.$prefixes[$x],$values[$x]));
                    }
                }
			}
		}
	}

	# Sort output by hostname
	if (!($o{'n'})) {
		# Sort those puppies!
		@result      = sort { (split /\s+/, $a)[2] cmp (split /\s+/, $b)[2] } @result;
		@exact       = sort { (split /\s+/, $a)[2] cmp (split /\s+/, $b)[2] } @exact;
		@firewall    = sort { (split /\s+/, $a)[2] cmp (split /\s+/, $b)[2] } @firewall;
		@firewalltop = sort { (split /\s+/, $a)[2] cmp (split /\s+/, $b)[2] } @firewalltop;
	}

	# Did we want all results?
	if ($o{'e'}) {
		# Exact only
		@result = @exact;
		# Yes, 'exact' applies to firewall matches also
		@firewall = @firewalltop;
	}
	else {
		# Prepend @exact to @result
		unshift(@result,@exact);
		unshift(@firewall,@firewalltop);
	}

	# Order firewall entries

	# Do we want firewall entries includes?
	if ($o{'f'}) {
		if (@firewall == 0) {
			push (@result,"\n  No matching firewall address book entries.");
		}
		else {
			# Add fw entries to the end
			if ($o{'t'}) {
				push(@result,"\n  Matching firewall address book entries:");
			} 
			else {
				push(@result,"\n  Matching firewall address book entries (excluding 10/8):");
			}
			push(@result,@firewall);
		}
	}

	if (@result == 0) {
		return "  No matches. Use -f to check firewall objects too." if ($not_minimal);
		return "unknown" if ($minimal);
	}
	else {
        if ($o{'g'}) {
            # Want first match, prefer exact
            # Remeber that @exact has already been prepended to @result
            # so the first line of @result will be the first match, exact or otherwise
            my $result = shift(@result);
            while ($result =~ /Subnet:/) {
                last if (@result == 0);
                $result = shift(@result);
            }
            if ($result =~ /Subnet:/){
                return "unknown";
            }
            else {
                return "\n$result";
            }
        }
        else {
            return "\n" . join("\n",@result);
        }
	}
} 

sub ip2bin {
    my $ip = $_[0];
    return     join("",  map substr(unpack("B32",pack("N",$_)),-8), split(/\./,$ip));
}

sub loguse {
	my $user = $ENV{LOGNAME} || $ENV{USER} || getpwuid($<);
	my $date = localtime(time());
	my $options = "";
	$options .= $o{'e'} ? "-e " : "   ";
	$options .= $o{'f'} ? "-f " : "   ";
	$options .= $o{'t'} ? "-t " : "   ";
    $options .= $o{'v'} ? "-v " : "   ";
        open (LOG,">>" . $dataDir . "/usage.log") || return;
	foreach my $ip (@ARGV) {
		print LOG sprintf("%10s   $date  $options  $ip\n",$user);	
	}
	close (LOG);	
}

sub displayInfo {
	# Display some standard information about the program version
	# and the data file version

	my $dbfile = 'ipbinary.db';     # Database file
	my $mtime;
	my $dataConversion = 'ip2bin.pl';

	# Count lines and grab header info
	my $totcount = 0;
	my @progDataSource;

	#print STDOUT "\n";

	# Run through the dataDar
	opendir(DIR,$dataDir);
	foreach my $file (readdir(DIR)) {
		next if ($file !~ /$dbExtension$/); # only read the ipbinary.db files
		my $count = 0;
		open (IN,$dataDir.'/'.$file) || die ("Can't check database file.\n");

		# Get last modification time for data file based on handle
		(undef,undef,undef,undef,undef,undef,undef,undef,undef,$mtime,undef,undef,undef) = stat(IN);
		# Make mtime readable
		$mtime = gmtime($mtime);
		$mtime =~ s/  / /g;


		while (my $line = <IN>) {
			chomp($line);
			# Deal with header lines (##)
			if ($line =~ /^##/) {
				# Grab timestamp
				if ($line =~ /Timestamp: (.*)$/) {
					# Override stat() time if available in data
					$mtime = $1;
				}
				elsif ($line =~ /DataSource: (.*)$/) {
					# Override data source if available in data
					$progDataSource = $1;
				}
				# Otherwise move on and ignore the header line
				next;
			}
			# All other lines just get counted
			$count++;
		}
		# Store source and timestamp
		push(@progDataSource,$progDataSource.' ('.sprintf("%5d",$count).') at ' . $mtime . ' UTC');
		$progDataSource = 'UNK';
		$mtime = 'unknown';
		$totcount += $count;
		close(IN);
	} # end foreach

	print STDOUT <<END;

       This Program: $progName, v$progVer
             Author: $progAuthor
  Latest Bug Finder: $latestbug (Woo! Yeah! Way to go!)

    Data Extraction: $dataGenerator
         Conversion: $dataConversion

 Total # IP entries: $totcount
END
	foreach my $source (sort @progDataSource) {	
		print STDOUT "     IP Data Source: $source\n";
	}
	print STDOUT "\n";

}
sub ipv62bin {
    # Take IP/mask in and expand all missing zeroes so we can then create 
    # a true binary representation of the 128-bit IP address
    my $ipadd = $_[0];
    my $expandOnly = $_[1] || 0;
    my $host; my $mask;

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
    if ($#elements >= 8) {
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
            # Might be a double colon; need to keep this blank for now
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
    #print "There are " . ($#elements + 1) . " elements. " . join('-',@elements) . "\n";
    if ($#elements < 7) {
        if ($host !~ /::/) {
            # We got here as if there's a ::, but there's no :: in the original string...
            return "Error: Host '$host' seems to be too short.";
        }

        # There should be 8 elements, so we can replace the missing element(s) 
        my $missing = (8 - $#elements); # Mathematically incorrect, but it works to add in the correct number

        foreach my $element (@elements) {
            if ($element eq '') {
                # Must be double colon; replace it!
                $element = '0000' x $missing;
            }
        }
    }

    #print "Final output: 123456789-123456789-123456789-12\n";
    #print "Final output: " . join('',@elements) . "\n";
    #print "Length is " . length(join('',@elements)) . "\n";
    if (length(join('',@elements))<32) {
        return "Error: IP address '$ipadd' is too short.\n";
    }
    if (length(join('',@elements))>32) {
        return "Error: IP address conversion for '$ipadd' went very wrong.\n";
    }


    # Convert the IP to binary fun
    # Takes 32-byte string of ipv6 hex nybbles (no colons!) and returns binary string equivalent
    # Nice little one-liner, I thought. Simpler than ipv4 because we already stripped out the
    # colons, so no need to split it up again
    #print STDERR "Yeah, it's all ok apparently.\n";
    if ($expandOnly) {
        # Returns raw IPv6 fully expanded address
        return join(':',@elements);
    }
    else {
        # Returns binary for fully expanded address
        return unpack('B128',pack('H32',join('',@elements)));
    }
}


