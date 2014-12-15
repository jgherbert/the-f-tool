#!/usr/bin/perl

# IP grabber - extract IP and mask information and map to device name and interface, for searching purposes
# John Herbert - September 2013 - December 2014
#
# Motto: ~~It sucks, but it's what we've got~~

use strict;
use DirHandle;

# Hub Site  (This site is the configuration hub, and hosts the manual additions)
# This feature not fully documentsed yet on github
my $HUBSITE = 'ATL';

# This is where the configurations are stored. For the real hosts it will be /data/network
my $path = '/data/network/config_gathering';
my $syspath = '/data/fdb/manual'; # Manually added configurations

# Basic program information
my $progVer = '1.5.4 - August 21, 2014';
my $progName = 'ipgrabber.pl';
my $progRunTime = gmtime(time());
$progRunTime =~ s/  / /g;
my $fcounter = 0;
my $dcounter = 0;
my $filemtime = '';

# v1.5.0 begins ipv6 support. Lord help us.

# Need to know what host we're running on so we can correctly identify the data
use Sys::Hostname;
my $sysHost = hostname;
$sysHost = (split(/\./,$sysHost))[0] if ($sysHost =~ /\./); # Just hostname please
my $dataSource = uc(substr($sysHost,0,3)) || "UNK";

# Define the output directory. I'm going to rudely store interim and final data in
# /data/fdb (the f database). The idea is that this path is constant on all hosts, and
# should be a safe place to use for the raw and binary data files.
my $dataDir = '/data/fdb';

# Prep vars
my %output;
my %dnsoutput;
my %masks;
defineMasks();


# Read the directories and store extracted IPs in %output
# First the regular /data/network path on each host
scanFiles($path,\%output,\%dnsoutput);
writeData($dataSource,\%output);
# In progress is the abiity to write out DNS names as well
writeData('DNS-'.$dataSource,\%dnsoutput);

undef %output; # Clear the old host data

# Now just for hub site, add in a scan of the 'manual' entries
if ($dataSource eq $HUBSITE) {
	scanFiles($syspath,\%output,\%dnsoutput);
	writeData('MAN',\%output);
	writeData('DNS-MAN',\%dnsoutput);
}

# Fat lady sings
exit();


sub scanFiles {
	my $path = $_[0];
	my $rawref = $_[1];
	my $dnsref = $_[2];
	my $dh = DirHandle->new($path);
	my $file;
    #print STDERR "Reading directory $path.\n";
	if (defined($dh)) {
		while (defined($file = $dh->read)) {
			#print STDERR ("reading file '$file'\n");
			next if ($file =~ /^\./); # ignore dot files 	
			next if ($file =~ /^old$/); # ignore old configurations

			# Recurse directories. The F5 archives I get are filled with stuff I don't 
            # want or need so I'm skipping it. This is, well, ugly.
            # YESTERDAY / PREVIOUS are config archives, so we skip them because we only want to
            # scan _today's_ archive
			if (-d $path.'/'.$file) {
				# Bunch of stuff to skip to make things faster...
				next if ($file eq 'YESTERDAY');     # Skip 'old' data
				next if ($file eq 'PREVIOUS');      # Skip 'old' data
				next if ($file eq 'UCS_CONFIGS');   # Skip legacy path
				next if ($file eq 'TMP');           # Skip 'old' data
				next if ($file eq 'OLD');           # Skip 'old' data
				next if ($file eq 'old');           # Skip 'old' data
				next if ($file eq 'log');           # Skip irrelevant stuff
				next if ($file eq 'wa');           # Skip irrelevant stuff
				next if ($file eq 'ssl');           # Skip irrelevant stuff
				next if ($file eq 'ssh');           # Skip irrelevant stuff
				next if ($file eq 'snmp');           # Skip irrelevant stuff
				next if ($file eq 'qkview');           # Skip irrelevant stuff
				next if ($file eq 'net-snmp');           # Skip irrelevant stuff
				next if ($file eq 'monitors');           # Skip irrelevant stuff
				next if ($file eq 'lost+found');           # Skip irrelevant stuff
				next if ($file eq 'httpd');           # Skip irrelevant stuff
				next if ($file eq 'gtm');           # Skip irrelevant stuff
				next if ($file eq 'failover');           # Skip irrelevant stuff
				next if ($file eq 'eav');           # Skip irrelevant stuff
				next if ($file eq 'dashboard');           # Skip irrelevant stuff
				next if ($file eq 'customization');           # Skip irrelevant stuff
				next if ($file eq 'bigpipe');           # Skip irrelevant stuff
				next if ($file eq 'big3d');           # Skip irrelevant stuff
				next if ($file eq 'aaa');           # Skip irrelevant stuff
				next if ($file eq 'tmp`');           # Skip irrelevant stuff
				# Otherwise:
				scanFiles($path.'/'.$file,$rawref,$dnsref);
				next;
			}

            # Is it a real file? Skip symlinks 
            next if (-l $path.'/'.$file);

            # Grab file last modified date
            my @stats = stat($path.'/'.$file);
            $filemtime = '  [['.isodate($stats[9]).']]';

			# Junos files
			if ($file =~ /junos(\.set)?$/) {
				readJunos($path.'/'.$file,$rawref,$dnsref);
				next;
			}
			# f5 files
			elsif ($file =~ /bigip(_base)?\.conf$/) {
				#print STDERR "F5: Processing $file.\n";
				readF5($path.'/'.$file,$rawref,$dnsref);
				next;
			}
			# screenos files
			elsif ($file =~ /netscreen|screenos/) {
				readScreenOS($path.'/'.$file,$rawref,$dnsref);
			}
            elsif ($file =~ /a10(\.log)?$/i) {
                #print "Reading A10 $file.\n";
                readA10($path.'/'.$file,$rawref,$dnsref);
            }
			# cisco files
			elsif ($file =~ /cisco(\.log)?$/i) {
				readCisco($path.'/'.$file,$rawref,$dnsref);
			}

		} # end while
	} # end if
	undef $dh;
}

sub readJunos {
	my $file = $_[0];
	my $rawref = $_[1];
	my $dnsref = $_[2];
	my %interfaces;
    my %vlans;
    my %vlan_id;
    my %deactivated;

	# Also grab routing-instances. For example:
	# set routing-instances s18-prd-be interface irb.1370
	# With a note that these appear AFTER the interface definitions (grrr)

	# We will extract the hostname from the filename (saves digging into the re0/re1 naming)
	# e.g. /Users/blah/bin/configs/network/switches/pod/sfo-accsw07.20130815.junos.set.
	my @temp = split(/\//,$file); # split on / to get last element (filename)
	my $hostname = pop(@temp); # snag last element
	($hostname,undef) = split(/\./,$hostname); # up to first dot should be the hostname. Job done.

    # Now, for hostnames ending in -re0 or -re1, let's strip that as it makes the output very ugly
    # and really it doesn't matter, as you only connect to the active re in any case...
    $hostname =~ s/-re[01]$//;

	# Create unique version of hostname, skipping the a/b at the end
	my $uniquehostname = $hostname;
	$uniquehostname =~ s/[ab]$//;

	open(JUNOS,$file) || die("Can't read Junos file $file. $!\n");
	my @junos = <JUNOS>; # slurp the file
	close(JUNOS);

	# Grab routing instances, l3 vlan interfaces and deactivated interfaces (first run through)
	foreach my $line (@junos) {
		if ($line =~ /set routing-instances ([\w\d\-_]+) (bridge-domains [\d\w\-_]+ )?interface ([\w\d\.\-\/]+)/) {
			# Store routing-instance with interface name
			$interfaces{$3} = $1;
            #print STDERR ("$hostname: Storing RI '$1' for intf $3\n");
			next;
		} 
        elsif ($line =~ /set (routing-instances [\w\d\-_]+ )?bridge-domains ([\w\d\-_]+) vlan-id (\d+)/) {
            #set bridge-domains VLAN-1057 vlan-id 1057
            my $vlanname = $2;
            my $vlan_id = $3;
            # Store the vlan_id indexed by vlanname
            $vlan_id{$vlanname} = $vlan_id;
        }
        elsif ($line =~ /set (routing-instances [\w\d\-_]+ )?bridge-domains ([\w\d\-_]+) routing-interface ([\w\d\.]+)/) {
            #set bridge-domains VLAN-1057 routing-interface irb.1057
            my $routinginstance = $1;;
            my $vlanname = $2;
            my $l3intf = $3;
            my $l3uintf  = $l3intf;
            $l3uintf =~ s/\./u/; # convert unit to a u for later matching
            # Find the vlan-id previously stored for this vlanname
            if ($vlan_id{$vlanname}) {
                $vlans{$l3uintf} = $vlan_id{$vlanname};
            }
            # While we're at it, the routing-interface is also implicitly in the routing-instance, isn't it? So let's
            # make sure and add that too if there was one:
            if ($routinginstance) {
                $routinginstance =~ s/^routing-instances //;
                $routinginstance =~ s/ //g;
                $interfaces{$l3intf} = $routinginstance; 
                #print STDERR "$hostname: Storing RI $routinginstance for intf $l3intf.\n";
            }
        }
        elsif ($line =~ /deactivate interfaces ([\w\d\-_\/]+) unit (\d+)/) {
            #deactivate interfaces irb unit 1900
            my $interface = $1;
            my $unit = $2;
            $interface .= 'u'.$unit;
            $deactivated{$interface} = 1;
            #print "Deactivating $hostname $interface\n";
        }
	}

	# Now look for interfaces/IP addressing (and we can map RIs to them as we go)
	foreach my $line (@junos) {
		# Look for the set lines listed above, to extract the IP address
		chomp($line);
        #set interfaces xe-0/3/1 unit 3000 vlan-id 3000
		if ($line =~ /^set interfaces ([\w\d\-\/]+) unit ([\d]+) vlan-id (\d+)/) {
            # Store VLAN ID for interface and unit
            my $int = $1;
            my $unit = $2;
            my $vlan = $3;
            $vlans{$int.'u'.$unit} = $vlan;
            #print STDERR "Storing vlan $vlan for $int.u.$unit\n";
        }
		elsif ($line =~ /^set interfaces ([\w\d\-\/]+) unit ([\d]+) family (inet[6]?) address ([a-f\d\.\:]+\/\d+) vrrp-group [\d]+ virtual-address ([a-f\d\.\:]+)/) {
			my $int = $1;
			my $unit = $2;
			my $prot = $3;
			my $rootadd = $4;
			my $add = $5;
            my $dnsadd = $rootadd;
            my $dnsvrrp = $add;
            my $dnsvlan = '';
            my $version = 'v4';
 
            # Check if this is a known deactivated interface
            if ($deactivated{$int.'u'.$unit}) {
                #print STDERR ("$hostname: Ignoring vrrp for $int\u$unit - deactivated\n");
                next;
            }
            
            # Check if we already found a vlan tag for this interface / unit.
            $dnsvlan = $vlans{$int.'u'.$unit} if ($vlans{$int.'u'.$unit});

            #print STDERR "$hostname: Found '$dnsvlan' for $int.u.$unit\n";

            #Don't do this now; we are supporting ipv6, right?!
            #next if ($prot eq 'inet6');
            # Instead, let's flag v6 formally
            $version = 'v6' if ($prot eq 'inet6');
            if ($version eq 'v6') {
                #print STDERR "Found a v6 address: $int unit $unit, $add.\n";
            }

			# Process rootadd to extract original interface's mask
			my $mask; (undef,$mask) = split(/\//,$rootadd,2);
			$add .= '/' . $mask; # Normalize address format

            # Remove prefix length from $dnsadd (don't need mask in dns)
            $dnsadd =~ s/\/\d+$//;

			my $intf = $int . '.' . $unit; 
            my $routinginstance = '';

            my $dnsaddname = "$hostname-$int";
            $dnsaddname =~ s/\//-/g;
            if ($unit ne "0") {
                if ($dnsaddname =~ /irb$/) {
                    $dnsaddname .= "$unit";
                }
                elsif ($dnsaddname =~ /vlan$/) {
                    $dnsaddname =~ s/vlan$/v/;
                    $dnsaddname .= "$unit";
                }
                else {
                    $dnsaddname .= "-u$unit";
                }
            }

			if ($interfaces{$intf}) {
                    # Evil hack to plonk the routing-instance on the end of the string
                    $unit .= ' (' . $interfaces{$intf} . ')';
                    $routinginstance = $interfaces{$intf};
            }
            else {
                #print STDERR ("$hostname: No routing-instance found for $intf\n");
            }

			# First of all dump the interface IP out
            $fcounter++;
			$$rawref{"$rootadd $hostname  $int.$unit$filemtime\n"}=1;

            my $dnsvrrpname = $dnsaddname . "-vrrp";
            if ($routinginstance) {
                $dnsaddname .= '--'.$routinginstance;
                $dnsvrrpname .= '--'.$routinginstance;
            }
            $dcounter++;
			$$dnsref{"$dnsadd,$dnsaddname,$dnsvlan,$routinginstance\n"}=1;

			# Now dump out the vrrp address
			$unit .= "-vrrp"; # Note that this is the vrrp address
            $dcounter++;
			$$dnsref{"$dnsvrrp,$dnsvrrpname,$dnsvlan,$routinginstance\n"}=1;
            $fcounter++;
			$$rawref{"$version:$add $hostname  $int.$unit$filemtime\n"}=1;

                        #print STDERR ("$add $hostname--$int.$unit $prot\n");

            next;
		}
		elsif ($line =~ /^set (groups )?(re[01] )?interfaces ([\w\d\-\/]+) unit (\d+) family (inet[6]?) address ([a-f\d\.\:]+\/\d+)/) {
			my $re = $2;
			my $int = $3;
			my $unit = $4;
			my $prot = $5;
			my $add = $6;
            my $dnsadd = $add;
            my $dnsvlan = '';
            my $version = 'v4';
            
            # Check if this is a known deactivated interface
            if ($deactivated{$int.'u'.$unit}) {
                #print STDERR ("$hostname: Ignoring IP for $int unit $unit - deactivated\n");
                next;
            }

            
            # Check if we already found a vlan tag for this interface / unit.
            $dnsvlan = $vlans{$int.'u'.$unit} if ($vlans{$int.'u'.$unit});

			$unit .= '-' . $re if ($re);

			# BUT - if we see vrrp in the line, we can assume that this has already been added in the clause above, right? Right.
			# This allows for the case where there's only a single line of vrrp/family inet configuration (e.g. nuq-csw01)
			# This little bug courtesy of a report from a friend, who pointed out that some interfaces may only show a
			# vrrp address, and not the interface address. It turned out that the script was finding the interface address
			# by matching on the subsequent lines (e.g. priority and accept-data), which are not always present.
			# Therefore:
			next if ($line =~ /vrrp/);
			
			# For now, ignore IPv6 (we'll come back to that later) once the indexing scripts
			# support it too
            #next if ($prot eq 'inet6');
            $version = 'v6' if ($prot eq 'inet6');

            # Remove prefix length from $dnsadd (don't need mask in dns)
            $dnsadd =~ s/\/\d+$//;

			# Check if we know a routing-instance for that interface
			my $intf = $int . '.' . $unit;

            my $routinginstance = '';
            my $dnsunit = $unit;
			#print STDERR "Compare interface '$int.$unit' with '$intf'\n";
			if ($interfaces{$intf}) {
				# Evil hack to plonk this on the end of the string
				$unit .= ' (' . $interfaces{$intf} . ')';
                $routinginstance = $interfaces{$intf};
				#print STDERR "Interface " . $int.'.'.$unit.": Match RI $interfaces{$intf}/n";
			}

            my $dnsaddname = '';
			if ($int =~ /^reth\d/) {
                $fcounter++;
				$$rawref{"$version:$add $uniquehostname\  $int.$unit$filemtime\n"}=1;
                $dnsaddname = "$uniquehostname-$int";
                $dnsaddname =~ s/\//-/g;
                if ($dnsunit ne "0") {
                    if ($dnsaddname =~ /irb$/) {
                        $dnsaddname .= "$dnsunit";
                    }
                    else {
                        $dnsaddname .= "-u$dnsunit";
                    }
                }
                $dnsaddname .= "--$routinginstance" if ($routinginstance);
                $dcounter++;
                $$dnsref{"$dnsadd,$dnsaddname,$dnsvlan,$routinginstance\n"}=1;
                $dnsadd = ''; $dnsaddname = '';
			}
			else {
                $fcounter++;
				$$rawref{"$version:$add $hostname\  $int.$unit$filemtime\n"}=1;
                $dnsaddname = "$hostname-$int";
                $dnsaddname =~ s/\//-/g;
                if ($dnsunit ne "0") {
                    if ($dnsaddname =~ /irb$/) {
                        $dnsaddname .= "$dnsunit";
                    }
                    elsif ($dnsaddname =~ /vlan$/) {
                        $dnsaddname =~ s/vlan$/v/;
                        $dnsaddname .= "$unit";
                    }
                    else {
                        $dnsaddname .= "-u$dnsunit";
                    }
                }
                $dnsaddname .= "--$routinginstance" if ($routinginstance);
                $dcounter++;
                $$dnsref{"$dnsadd,$dnsaddname,$dnsvlan,$routinginstance\n"}=1;
                $dnsadd = ''; $dnsaddname = '';
			}
			#print STDERR ("$add $hostname--$int.$unit $prot\n");
			next;
		}
		elsif ($line =~ /^set security zones security-zone (\w+) address-book address ([\d\w\.\/]+) ([\d\/\.]+)/) {
			# Zone-specific firewall address-book entries. Why not, right?
			my $zone = $1;
			my $name = $2;
			my $add = $3;
			$$rawref{"$add $uniquehostname\  {FW} $name ($zone zone)$filemtime\n"}=1;
			next;
		}
		elsif ($line =~ /^set security address-book global address ([\d\w\.\/]+) ([\d\/\.]+)/) {
			# Global firewall address-book entries. Why not, right?
			my $name = $1;
			my $add = $2;
			$$rawref{"$add $uniquehostname\  {FW} $name (global)$filemtime\n"}=1;
			next;
		}
		elsif ($line =~ /^set security nat source pool ([\d\w\-\_]+) address ([\d\/\.]+)/) {
			my $natname = $1;
			my $natpool = $2;
			my $natend = "";
			# Check for source NAT pool in 'hard' format (with a "to <ip>" clause on the end)
			if ($line =~ / to ([\d\/\.]+)/) {
				$natend = $1;
			}
			# Can we assume that all "x to y" format use /32? Seems to make sense, so we could just 
			# add lots of /32 ranges to the output file, with each one mapping back to the pool name.
			# It's ugly, but whatcha gonna do? We should flag up if we find anything other than /32 
			# though
			if ($natend) {
				# Process member IPs
				# Cross fingers, and rudely assume last octet only, I hope. Makes the math simpler.
				my $start; my $end;
				my $startip; my $endip;
				my $startmask; my $endmask;

				#print STDERR "Found NAT range $natpool to $natend;\n"; 

				$natpool =~ /([\d\.]+)\/([\d]+)/;
				$startip = $1; $startmask = $2;

				$natend  =~ /([\d\.]+)\/([\d]+)/;
				$endip = $1; $endmask = $2;

				#print STDERR "  decoded as: $startip / $startmask to $endip / $endmask.\n";

				if ($startmask ne "32") {
					warn "Found non-/32 mask ($startmask) for $hostname: $line\n";
				}

                my @iparray;
                expandIPRange($startip,$endip,\@iparray);
				foreach my $rangeip (@iparray) { 
					$$rawref{"$rangeip/$startmask $uniquehostname  NAT Pool ($natname)$filemtime\n"}=1;
				}	
			}
			else {
				# Simple entry addition
				$$rawref{"$natpool $uniquehostname  NAT Pool ($natname)$filemtime\n"}=1;
			}

		}
	}
} # end readJunos

sub readF5 {
	my $file = $_[0];
	my $rawref = $_[1];
	my %interfaces;

	# For these we have to extract the hostname from the path at which it's stored because each config
    # file does not contain the hostname definition, helpfully enough. In this case I look for 
    # "UCS_CONFIG" in the path and filter from there

	my $hostname = '';

	# Check for UCS_CONFIG first:
	if ($file =~ /\/UCS\//) {
		# Extract the hostname from the filepath. The format is:
		# /..blah../UCS/LATEST/<hostname>/.../bigip(_base).conf
		# This isn't my proudest hour, but this turns out to be quite reliable,
		# even if it's a candidate for a perl obfuscation contest in itself.
		# TMTOWTDI, remember:

		$hostname = ( split(/\//, ( split(/\/LATEST\//,$file) )[-1] ) )[0];

		# print STDERR ("f5> Found host '$hostname' in UCS path. Path was:\n   $file\n");
	}
	else {
		# Treat as regular f5 config file with name in the hostname
		my @temp = split(/\//,$file); # split on / to get last element (filename)
		$hostname = pop(@temp); # snag last element. Yes, I know I could do that in one line without @temp. Work with me here.
		($hostname,undef) = split(/_/,$hostname); # up to first _ should be the hostname. We may need to strip off domain name afterwards

	}

	# Check for dots (suggesting fqdn) and strip anything after the hostname
	($hostname,undef) = split(/\./,$hostname,2) if ($hostname =~ /\./);


	if ($hostname eq '') {
		# Aww crap
		warn("Failed to get f5 hostname from '$file'.");
		return;
	}

	my $uniquehostname = $hostname;

	# 2013-09-16: Today's new pain in the butt is that v11 config files are formatted quite differently to v10. Joy!

	open(F5,$file) || die("Can't read f5 file $file. $!\n");

	my $partition = "";
	my $version = "";

	# Loop time (and many sub-loops; joy)
	while (my $line =<F5>) {
		if ($line =~ /^shell write partition ([\w\d\-_]+)/) {
			$partition = $1;
			$version = 10; # Flag code version to help with using right decodes
			#print STDERR ("  Found partition $partition.\n");
			next;	
		}
		if ($version == 10) {
			if ($line =~ /^self ([\d\.]+)(%[\d+])? \{/) {
				my $ip = $1;
				# Found a self IP - need a netmask now
				my $netmask;
				my $prefix;
				my $vlan;
				until ($line =~ /^\}/) {
					$line = <F5>;
					if ($line =~ /netmask ([\d\.]+)/) {
						# Found netmask; use it
						$netmask = $1;
						# Convert netmask to prefix
						$prefix = mask2prefix($netmask);
					}
					elsif ($line =~ /vlan ([\w\d\-\_]+)/) {
						$vlan = $1;
						# Dump output now
						$$rawref{"$ip/$prefix $uniquehostname  SelfIP (Part:$partition, VLAN:$vlan)$filemtime\n"}=1;
					}
				}

			}
			elsif ($line =~ /^node ([\d\.]+)(%[\d+])?/) {
				my $ip = $1;
				# Found a node IP, assume /32
				$$rawref{"$ip/32 $hostname  LB_Node (Part:$partition)$filemtime\n"}=1;
			}
			elsif ($line =~ /virtual ([\w\d\.\-_]+) \{/) {
				my $vname = $1;
				my $ip;
				# Found a virtual server; scan until we find destination line
				until ($line =~ /^\}/) {
					$line = <F5>;
					if ($line =~ /destination ([\d\.]+)(\%[\d]+)?:/) {
						$ip = $1;		
						# Write out line
						$$rawref{"$ip/32 $hostname  VIP $vname (Part:$partition)$filemtime\n"}=1;
					}

				}
			}
			elsif ($line =~ /snatpool ([\w\d\.\-_]+) \{/) {
				my $snatpool = $1;
				my $ip;
				# Found a snatpool. Loop and look for members
				until ($line =~ /^\}/) {
					$line = <F5>;
					if ($line =~ /\s+([\d\.]+)(\%[\d]+)?/) {
						$ip = $1;
						# Dump member out
						$$rawref{"$ip/32 $hostname  SNATpool $snatpool (Part:$partition)$filemtime\n"}=1;
					}
				}
			}
			elsif ($line =~ /snat ([\w\d\.\-_]+) \{/) {
				my $snat = $1;
				# print STDERR "Found SNAT: $snat\n";
				my $ip;
				until ($line =~ /^\}/) {
					$line = <F5>;
					if ($line =~ /translation ([\d\.]+)(\%[\d]+)?/) {
						$ip = $1;
						$$rawref{"$ip/32 $hostname  SNAT $snat (Part:$partition)$filemtime\n"}=1;
					}
				}
			}
		} # end if v10
		else {
			# Assume v11
			if ($line =~ /^net self \/([\w\d\-\._]+)\/([\w\d\-_]+)/) {
				# v11 self address. Need to grab the partition and name, then the address is
				# on the next line
				$partition = $1;
				my $interface = $2;
				my $ip; my $vlan;
                my $version = 'v4';
				until ($line =~ /^\}/) {
					$line = <F5>;
					# Newer configs have the IP stored as e.g. 1.2.3.4%30/29
					$line =~ s/%\d+//; # Strip out stupid #nn partition reference when stuffed in the middle of an IP!
					if ($line =~ /address ([\d\.\/]+)/) {
						$ip = $1;
					}
                    elsif ($line =~ /address ([0-9a-f:]+)/i) {
                        $ip = $1;
                        $version = 'v6';
                    }
					elsif ($line =~ /vlan \/[\w\d\-_]+\/([\w\d\-\._]+)/) {
						$vlan = $1;
						# Dump this all out, currenlty ignoring the $interface value...
						# But only if the IP has ',' in it (i.e. it's IPv4):
						if ($ip =~ /\./) {
							$$rawref{"$version:$ip $uniquehostname  SelfIP (Part:$partition, VLAN:$vlan)$filemtime\n"}=1;
						}
					}
				}
				next;
			}
			elsif ($line =~ /^ltm node \/([\w\d\-\._]+)\/([\w\d\-\_\.]+) \{/) {
				# Found a node entry
				my $partition = $1;
				my $nodename = $2;
                my $version = 'v4';
				until ($line =~ /^\}/) {
					$line = <F5>;
					if ($line =~ /address ([\d\.]+)/) {
						my $ip = $1;
						# Dump this all out
						$$rawref{"$version:$ip/32 $hostname  LB-Node $nodename (Part:$partition)$filemtime\n"}=1;
					}
                    elsif ($line =~ /address ([0-9a-f:]+)/i) {
                        my $ip = $1;
                        $version = 'v6';
						# Dump this all out
						$$rawref{"$version:$ip/128 $hostname  LB-Node $nodename (Part:$partition)$filemtime\n"}=1;
                    }
				}
				next;
			}
			elsif ($line =~ /^ltm snat-translation \/([\w\d\-\._]+)\/([\w\d\-\_\.]+) \{/) {
				# Found a snat. Going to ignore the pool member names for the moment
				my $partition = $1;
				my $snat  = $2;
				until ($line =~ /^\}/) {
					$line = <F5>;
					if ($line =~ /address ([\d\.]+)/) {
						my $ip = $1;
						# Dump this all out
						$$rawref{"v4:$ip/32 $hostname  SNAT $snat (Part:$partition)$filemtime\n"}=1;
					}
					elsif ($line =~ /address ([0-9a-f:]+)/i) {
						my $ip = $1;
						# Dump this all out
						$$rawref{"v6:$ip/128 $hostname  SNAT $snat (Part:$partition)$filemtime\n"}=1;
					}
				}
				next;
			}
			elsif ($line =~ /^ltm snatpool \/([\w\d\-\._]+)\/([\w\d\-\_\.]+) \{/) {
				# Found a snatpool. 
                # Need to add ipv6 support yet...
				my $partition = $1;
				my $snatpool = $2;
				until ($line =~ /^\}/) {
					$line = <F5>;
					if ($line =~ /\/[\w\d\-\._]+\/([\d\.]+)/) {
						my $ip = $1;
						# Dump this all out
						$$rawref{"$ip/32 $hostname  SNATpool $snatpool (Part:$partition)$filemtime\n"}=1;
					}
				}
				next;
			}
			elsif ($line =~ /^ltm virtual \/([\w\d\-\._]+)\/([\w\d\-\_\.]+) \{/) {
				# Found a virtual server. 
				my $partition = $1;
				my $virtualname = $2;
				# Find destination line
				until ($line =~ /^\}/) {
					$line = <F5>;
					if (
                        ($line =~ /destination \/[\w\d\-\._]+\/([\d\.]+)(%\d+)?:/)
                        ||
					    ($line =~ /destination \/[\w\d\-\._]+\/([0-9a-f:]+)(%\d+)?\./)
                       )
                    {
						my $ip = $1;
                        # for v4 the format is a.b.c.d(%x)?:port
                        # for v6 it's a:b::c:d(%x)?.port
                        # FFS.
						if ($ip =~ /\./) {
							# IPv4
							# Strip the port information
							$ip =~ s/:[\d]+$//;
							# Dump this all out
							$$rawref{"v4:$ip/32 $hostname  VIP $virtualname (Part:$partition)$filemtime\n"}=1;
						}
						elsif ($ip =~ /:/) {
                            # IPv6
							# Strip the port information
							$ip =~ s/\.\d+$//;
							# Dump this all out
							$$rawref{"v6:$ip/128 $hostname  VIP $virtualname (Part:$partition)$filemtime\n"}=1;
                        }
					}
				}
				next;
			}
		}
	}

	close(F5);

} # end readF5

sub mask2prefix {
	my $mask = $_[0];
	my $prefix;
	my @octets;
	@octets = split(/\./,$mask);
	foreach my $octet (@octets) {
		# Increment value by bits in mask octet
		$prefix += $masks{$octet} . '.';
	}
	return $prefix;
}

sub defineMasks {
	$masks{'255'} = 8;
	$masks{'254'} = 7;
	$masks{'252'} = 6;
	$masks{'248'} = 5;
	$masks{'240'} = 4;
	$masks{'224'} = 3;
	$masks{'192'} = 2;
	$masks{'128'} = 1;
	$masks{'0'} = 0;
}

sub readScreenOS {
	my $file = $_[0];
	my $rawref = $_[1];
	my %interfaces;

	# Let's extract the hostname from the config since I don't know the file naming standard yet

	my $uniquehostname = "";
	my $hostname = "";
	my %zone; # Store zone per interface
	my %tag; # Store tag per interface (if exists)
	my %mask; # store interface masks for use with manage-ip

	#Helpfully, the hostname sometimes comes after interface IPs. No idea why.
	#Read once until we find hostname, then process again for everything else.

	open(SCREENOS,$file) || die("Can't read ScreenOS file $file. $!\n");
	while (my $line = <SCREENOS>) {
		$line =~ s///g;
		if ($line =~ /^set hostname ([\w\d\-\.]+)$/) {
			# Found hostname
			$hostname = $1;
			$uniquehostname = $hostname;
			$uniquehostname =~ s/[ab]$//; # Strip a/b off the end
			#print STDERR "ScreenOS Hostname is $hostname.\n";
			last;
		}
	} # wend
	close(SCREENOS);

	open(SCREENOS,$file) || die("Can't read ScreenOS file $file. $!\n");
	while (my $line = <SCREENOS>) {
		$line =~ s///g;
		chomp($line);
		if ($line =~ /^set interface "([\w\d\/\.]+)" (tag \d+ )?zone "([\w\d\/\-\.]+)"/) {
			# Got an interface plus tag (perhaps) and zone
			my $interface = interfaceShorten($1);
			my $tag = $2;
			my $zone = $3;
			$tag =~ s/(tag|\s)//g; # strip tag and space
			#print STDERR "Line $line\n=> Int '$interface', Tag '$tag', Zone '$zone'\n";
			$zone{$interface} = $zone;
			$tag{$interface} = $tag;
		}
		elsif ($line =~ /^set interface ([\w\d\.\/]+) (manage-)?ip ([\d\.]+)(\/\d+)?/ ) {
			# Interface IPs
			my $int = interfaceShorten($1);
			my $ip = $3;
			my $mask = $4;
			my $intname = $int;
			if ($mask) {
				$ip .= $mask;
				$mask{$int} = $mask;
			}
			else {
				$ip .= $mask{$int};
				$intname .= " (manage-ip)";
			}
			#print STDERR "Interface=$intname, IP=$ip, tag=$tag{$int}, zone=$zone{$int}\n";

			# Clear the tag if there isn't one (untagged intf)
			my $tag = "";
			$tag = 'tag-' . $tag{$int} . ' ' if ($tag{$int});
			
			# Write out the IP
			if ($intname eq "mgt") {
				$$rawref{"$ip $hostname  $intname $tag(zone:$zone{$int})$filemtime\n"}=1;
			}
			else {
				$$rawref{"$ip $uniquehostname  $intname $tag(zone:$zone{$int})$filemtime\n"}=1;
			}
		}
		elsif ($line =~ /^set interface ([\w\d\.\/]+) ext ip ([\d\.]+) ([\d\.]+) dip ([\d\.]+) ([\d\.]+)/) {
			#print STDERR "Found DIP pool. \n";
			my $int = interfaceShorten($1);
			my $extip = $2;
			my $extmask = $3;
			my $dipid = $4;
			my $start = $4;
			my $end = $4;
			my $ip = $extip . '/' . mask2prefix($extmask);
			# Write out extip at least
			$$rawref{"$ip $uniquehostname  $int DIP$dipid (zone:$zone{$int})$filemtime\n"}=1;
		}
		elsif ($line =~ /^set address "([\w\d\-\.]+)" "([\w\d\-\._]+)" ([\d\.]+) ([\d\.]+)/) {
			# Address book entry
			my $zone = $1;
			my $name = $2;
			my $ip = $3;
			my $mask = $4;
			$ip .= '/' . mask2prefix($mask);
			#print STDERR "Found address book entry $name.\n";
			# Write out extip at least
			$$rawref{"$ip $uniquehostname  {FW} $name ($zone)$filemtime\n"}=1;
		}
	} # wend
	close(SCREENOS);
}

sub interfaceShorten {
	my $int = $_[0];
	# Make interface names a little more compact
	$int =~ s/tengigabitethernet/ten/i;
	$int =~ s/gigabitethernet/gig/i;
	$int =~ s/fastethernet/fas/i;
	$int =~ s/ethernet/eth/i;
	$int =~ s/loopback/lo/i;
	return $int;
}

sub writeData {
	# Dump output to a file
	my $dataSource = $_[0];
	my $hashrefOutput = $_[1]; # reference to %output passed in call to sub
	
	# Open the output file for writing
	open (OUT,">".$dataDir.'/'.$dataSource.'.ipdata.raw') || die("Cannot write output file. $!\n");

	# Last printout to STDOUT (fix later to go to a file, perhaps)
	print OUT "## Generator: $progName, v$progVer ($sysHost)\n";
	print OUT "## Timestamp: $progRunTime\n";
	print OUT "## DataSource: $dataSource\n";
	print OUT sort keys (%$hashrefOutput) if ($ARGV[0] ne "-q");

	# Close output file
	close(OUT);
}

sub readCisco {
	my $file = $_[0];
	my $rawref = $_[1];

	my %interfaces;
    my %masks; # Store interface/masks for use with vrrp/hsrp config on nxos style devices

	# Let's extract the hostname from the config since I don't know the file naming standard yet
	# Thankfully the hostname is high up in the configuration - before any IPs are defined
	# So we don't need to read it separately

	my $uniquehostname = "";
	my $hostname = "";

	open (CISCO,$file) || die ("Can't read file $file. $!\n");
	my $interface;
	my $vrf = '';
	my $nxosrp = ''; # use to track nsox vrrp|hsrp
	my @nxoslast; # store vrrps in case need to delete them
	my $intmask = '';

	while (my $line = <CISCO>) {
		if ($line =~ /^hostname (.*)$/) {
			$hostname = $1;
		}
		elsif ($line =~ /^ ?interface (.*)$/) {
			$interface = interfaceShorten(lc($1));
			$vrf = '';
			$nxosrp = '';
			@nxoslast = '';
			$intmask = '';
		}
		elsif ($line =~ /^\s*ip vrf forwarding (.*)$/) {
			# ios vrf 
			$vrf = ' ('.$1.')';
		}
		elsif ($line =~ /^\s*vrf member (.*)$/) {
			# nxos vrf
			$vrf = ' ('.$1.')';
		}
		elsif ($line =~ /^\s*vrf (.*)$/) {
            # ios-xr vrf
			$vrf = ' ('.$1.')';
        }
		elsif ($line =~ /^\s*ip(v4)? address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$/) {
			# Mask format
			my $ip = $2;
			my $mask = mask2prefix($3);
			$intmask = $mask;
			# Dump output
			#print STDERR "$hostname, $interface, IP=$ip/$mask$vrf\n";
			$$rawref{"v4:$ip/$mask $hostname  $interface$vrf$filemtime\n"}=1;
            # Store the mask for potential later use
            $masks{$interface} = $mask; # Perpetual, rather than $intmask which is very temporary
		}
		elsif ($line =~ /^\s*ip address (\d+\.\d+\.\d+\.\d+)\/(\d+)$/) {
			# Prefix format
			my $ip = $1;
			my $mask = $2;
			$intmask = $mask;
			# Dump output
			#print STDERR "$hostname, $interface, IP=$ip/$mask$vrf\n";
			$$rawref{"v4:$ip/$mask $hostname  $interface$vrf$filemtime\n"}=1;
		}
		elsif ($line =~ /^\s*(vrrp|standby) \d+?\s?ip (\d+\.\d+\.\d+\.\d+)\b/) {
			my $rp = $1;
			my $ip = $2;
			$rp = 'hsrp' if ($rp eq 'standby');
			if ($line =~ /secondary/) {
				# Dump secondary
				#print STDERR "$hostname, $interface, Standby IP=$ip/32 (secondary)$group$vrf\n";
				$$rawref{"v4:$ip/$intmask $hostname  $interface-$rp-sec$vrf$filemtime\n"}=1;
			}
			else {
				# Dump primary standby
				#print STDERR "$hostname, $interface, Standby IP=$ip/32$group$vrf\n";
				$$rawref{"v4:$ip/$intmask $hostname  $interface-$rp$vrf$filemtime\n"}=1;
			}
		}
		elsif ($line =~ /^\s*(hsrp|vrrp)\s\d+$/) {
			# NXOS style configuration
			$nxosrp = $1;
			# Now we'll loop and look for addresses
		}
		elsif ($line =~ /^\s+shutdown$/ && ($nxosrp)) {
			# xxrp is shutdown, so ignore it now 
			$nxosrp = '';

			# Now delete what we already added for this interface (if any)
			if ($#nxoslast > 0) {
				#print STDERR "Running array on " . $#nxoslast . " array items...\n";
				foreach (@nxoslast) {
					delete $$rawref{$_};
				}
				@nxoslast = '';
			}
		}
		elsif ($line =~ /^\s+address (\d+\.\d+\.\d+\.\d+)$/ && ($nxosrp)) {
			# Should be the xxrp address
			my $ip = $1;
			# Dump data
            my $themask = '32';
            $themask = ($masks{$interface}) if ($masks{$interface});
			if ($line =~ /secondary/) {
				$$rawref{"$ip/$themask $hostname  $interface-$nxosrp-sec$vrf$filemtime\n"}=1;
				# Store in case we need to retract when we find a 
				push(@nxoslast,"v4:$ip/$themask $hostname  $interface-$nxosrp-sec$vrf\n");
			}
			else {
				$$rawref{"$ip/$themask $hostname  $interface-$nxosrp$vrf$filemtime\n"}=1;
				push(@nxoslast,"v4:$ip/$themask $hostname  $interface-$nxosrp$vrf\n");
			}
		}
		
	} # wend
	close (CISCO);

} # end readCisco

sub expandIPRange {
    # Take start and end IP and expand them into a array of all the included IPs
    # Ideal for those pesky NAT ranges...
    my $startip  = shift;
    my $endip    = shift;
    my $arrayRef = shift;

    # Need to convert IPs to decimals so we can increment it
    my $startdec = ip2dec($startip);
    my $enddec = ip2dec($endip);

    #print "Start ($startip) is $startdec\nEnd ($endip) is $enddec.\n";

    for (my $x=$startdec; $x<=$enddec; $x++) {
        push(@$arrayRef,dec2ip($x));
    }
} # end expandIPRange

sub dec2ip {
    # Convert decimal value to an IP
    join '.', unpack 'C4', pack 'N', shift;
} # end dec2ip


sub ip2dec {
    # Convert IP to a decimal value
    unpack N => pack CCCC => split /\./ => shift;
} # end ip2dec

sub readA10 {
    # Guess what this reads? I know, right?
	my $file = $_[0];
	my $rawref = $_[1];

	my %interfaces;
    my %masks; # Store interface/masks for use with vrrp/hsrp config on nxos style devices


	# Let's extract the hostname from the config 
	# Thankfully the hostname is high up in the configuration - before any IPs are defined
	# So we don't need to read it separately

	my $uniquehostname = "";
	my $hostname = "";

	my $interface;
	my $vrf = '';
	my $nxosrp = ''; # use to track nsox vrrp|hsrp
	my @nxoslast; # store vrrps in case need to delete them
	my $intmask = '';
    my $vmaster = '';
    my %a10hostnames;
    my $nonmaster = 0;
    my $devicename = '';
    my $vservername = '';
    my $vserverip = '';
    my $vservervrid = '';
    my $vserverport = '';
    my $vserverprotocol = '';

	open (A10,$file) || die ("Can't read file $file. $!\n");
    #print "Processing A10 file.\n";
	while (my $line = <A10>) {
        $line =~ s/\r//g; # remove crappy \r
        chomp($line); # trim
        $line =~ s/\s+$//; # remove trailing spaces (Bad A10! Bad A10! No cookies for you!)
        if ($line =~ /^vcs vMaster-id (\d+)$/) {
            # Master chassis ID
            $vmaster = $1;
        }
        elsif ($line =~ /vcs local-device (\d+)$/) {
            # If this chassis ID is the master, then proceed.
            # Otherwise, move on as it's going to be duplicate
            if ($1 != $vmaster) {
                # Mark as nonmaster, but we have to continue to grab the other device hostnames
                #print("Found non-master A10 device number $1 (master is $vmaster).\n");
                $nonmaster = 1;
            }
        }
        elsif ($line =~ /^hostname (.*) device (\d+)/) {
            # Only match on the 'device N' master hostname so we don't get dupe entries
            $hostname = $1;
            $a10hostnames{$2} = $hostname; # Store hostname for later use (e.g. mgmt IPs)
        }
        elsif ($line =~ /^vlan /) {
            # We have now passed the section with cluster information and if we are on the non-master,
            # we can now return.
            if ($nonmaster) {
                #print("Non-master A10: Skipping rest of configuration.\n");
                return;
            }
        }
        elsif ($line =~ /interface management device (\d+)/) {
            # We're going to find an IP address and match it with the mgmt interface
            # *and* the correct device name based on the device-ids we stored earlier.
            # It's a plan so cunning you could stick a tail on it and call it a weasel.
            $devicename = $a10hostnames{$1}; # grab the devicename we need to use as override
			$interface = 'mgmt';
			$vrf = '';
			$nxosrp = '';
			@nxoslast = '';
			$intmask = '';
        }
        elsif ($line =~ /interface ve ([\d\/]+)/) {
            # We're going to find an IP address and match it with the mgmt interface
            # *and* the correct device name based on the device-ids we stored earlier.
            # It's a plan so cunning you could stick a tail on it and call it a weasel.
            $devicename = $a10hostnames{$1}; # grab the devicename we need to use as override
			$interface = 've-'.$1;
			$vrf = '';
			$nxosrp = '';
			@nxoslast = '';
			$intmask = '';
        }
		elsif ($line =~ /^\s*ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$/) {
            my $ip = $1;
            my $netmask = $2;
            my $mask = mask2prefix($netmask);
            if ($devicename) {
                # Override hostname
                $$rawref{"v4:$ip/$mask $devicename  $interface$vrf$filemtime\n"}=1;
            }
            else {
                $$rawref{"v4:$ip/$mask $hostname  $interface$vrf$filemtime\n"}=1;
            }
            # Reset the devicename now we used it for the management intf
            $devicename = '';
        }
		elsif ($line =~ /^\s*ipv6 address ([\d:]+)\/([\d+])$/) {
            my $ip = $1;
            my $mask = $2;
            if ($devicename) {
                # Override hostname
                $$rawref{"v6:$ip/$mask $devicename  $interface$vrf$filemtime\n"}=1;
            }
            else {
                $$rawref{"v6:$ip/$mask $hostname  $interface$vrf$filemtime\n"}=1;
            }
            # Reset the devicename now we used it for the management intf
            $devicename = '';
        }
        elsif ($line =~ /^ip nat pool ([\w\d\-_]+) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) netmask \/(\d+)\s+vrid (\d+)$/) {
            # Sample nat pool:
            # ip nat pool vrid1_snat 10.201.2.1 10.201.2.126 netmask /25  vrid 1
            my $natname = $1;
            my $startip = $2;
            my $endip = $3;
            my $mask = $4;
            my $vrid = $5;
            # Unlike Junos, A10 actually puts a proper netmask on the line rather than the bizarre /32 thing.
            if ($startip eq $endip) {
                # Only one address
                $$rawref{"v4:$startip/$mask $hostname  NAT Pool $natname (vrid-$vrid)$filemtime\n"}=1;
            }
            else {
                my @iparray;
                expandIPRange($startip,$endip,\@iparray);
                foreach my $rangeip (@iparray) {
                    $$rawref{"v4:$rangeip/32 $hostname  NAT Pool $natname (vrid-$vrid)$filemtime\n"}=1;
                }	
            }
        }
        elsif ($line =~/slb server (.*) (\d+\.\d+\.\d+\.\d+)$/) {
            # Not actually sure if we want to do this or not
            # Sample slb server:
            # slb server ams05rdns01 10.200.3.11
            my $servername = $1;
            my $ip = $2;
            $$rawref{"v4:$ip/32 $hostname  SLB Server ($servername)  $filemtime$filemtime\n"}=1;
        }
        elsif ($line =~ /slb virtual-server (.*) (\d+\.\d+\.\d+\.\d+)$/) {
            # Sample virtual server
            # slb virtual-server _10.201.0.2_vserver 10.201.0.2
            # Need to store this so that we can associate the following protocols/ports/vrids before writing
            $vservername = $1;
            $vserverip = $2;
            #print "Found vserver $vserverip as $vservername\n";
        }
        elsif ($line =~ /^\s{3}vrid (\d+)$/) {
            if ($vservername) {
                # Only do this if we're in the middle of a vserver block
                # Squirrel that vrid away like the name and IP
                $vservervrid = $1;
            }
        }
        elsif ($line =~ /^\s{3}port\s+(\d+)\s+([a-zA-Z\-\_]+)$/) {
            # More squirreling
            if ($vservername) {
                # Only do this if we're in the middle of a vserver block
                $vserverport = $1;
                $vserverprotocol = $2;
                #print "Found port $vserverport / $vserverprotocol for $vserverip\n";
            }
        }
        elsif ($line =~ /^\s{6}(name|source-nat|template|service-group) (.*)$/) {
            # Fin-a-bloody-ly, we have enough info to write something out!
            if ($vserverport) {
                #print "Storing port $vserverport / $vserverprotocol for $vserverip\n";
                $$rawref{"v4:$vserverip/32 $hostname  VIP $vservername ($vserverprotocol/$vserverport, vrid-$vservervrid)$filemtime\n"}=1;
                # Reset port/protocol as there may be another one to follow!
                $vserverport = '';
                $vserverprotocol = '';
            }
            # Else, do nothing
        }
        elsif ($line =~ /^!$/) {
            # Reset the many 'carry-over' variables
            $vservername = '';
            $vserverip = '';
            $vservervrid = '';
            $vserverport = '';
            $vserverprotocol = '';
        }
    } # wend
    close (A10);
} # end readA10

sub isodate {
    my $date = shift;
    # Temporarily do this the crap way because of lack of DateTime.pm availability
    #my $dt = DateTime->from_epoch(epoch =>$date);
    #return $dt->ymd('-');
    my @time = gmtime($date);
    #    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
    my $year = $time[5]+1900;
    my $mon = sprintf("%02d",$time[4] + 1);
    my $mday = sprintf("%02d",$time[3]);
    return($year.'-'.$mon.'-'.$mday);
} # end isodate
