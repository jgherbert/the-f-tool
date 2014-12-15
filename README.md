#F

*f*  - a short alias to an IP search script. Can be used as a transitive verb.
>Example: "*I don't know where that dang IP is located. F it.*"
>
>Example: "*That guy has to process so many firewall rules, it's like he'll F anything that moves.*"

The *f* tool is currently composed of three main elements, along with supporting scripts:

## 1 - ipgrabber.pl ##
This tool parses network device configuration files and generates a data file (*XXX.ipdata.raw*) linking IP/Subnet to a description. Beyond just an IP, the parser gathers additional contextual information - e.g. rather than just an IP and an interface/hostname, *ipgrabber.pl* will extract information such as routing-instance, partition, and similar - things that would take multiple CLI commands to otherwise determine. It also parses firewall address book and NAT objects so that they can be reported also. The source "site" name is derived at runtime using the first three chars of the origin hostname, converted to uppercase, e.g. SFO or ATL. This is a special snowflake hack that you may need to change in your environment. 

Configuration files by default are assumed to be located at /data/network/ on the machine on which ipgrabber.pl is executed. Again, this can be edited as needed.

#### Inputs ####

- Configuration file archive located at /data/network/ 

#### Outputs ####

- */data/fdb/XXX.ipdata.raw* 

## 2 - ip2bin.pl ##
This tool converts the local */data/fdb/XXX.ipdata.raw* file into a "pseudo-binary" format (stop laughing at the back) so that the IP and subnet are pre-converted for speedy IP comparisons by the user-facing search script (ipcheck.pl). The output file is stored along side the raw data as */data/fdb/XXX.ipbinary.db*. Even if multiple XXX.ipdata.raw files exist in the directory, the hostname again is used to identify the site, so the ATL host will only ever process "ATL.ipdata.raw". 

#### Inputs ####

- */data/fdb/XXX.ipdata.raw*

#### Outputs ####

- */data/fdb/XXX.ipbinary.db* 

## 3 - ipcheck.pl (usually called via a wrapper or alias called 'f') ##
This tool takes an IP on the command line and compares it to the IPs in the various *XXX.ipbinary.db* files stored in /data/fdb/. If there are multiple configuration archives being processed, the ipbinary.db file is what should be copied to the search location from each source in order to automatically search all extracted IPs.

Matching results include exact matches as well as any other entries where the supplied IP would exist on the same subnet as a known device interface or other processed network object.

Added in v1.1.3, the -m (minimal) argument makes ipcheck return nothing but a hostname or "unknown" for use in inline applications.

#### Inputs ####

- User-supplied IP query
- *XXX.ipbinary.db* files on the host where the command is run

#### Outputs ####

- Query results delivered to STDOUT in a textual format. Future code may provide data in a structured format for programmatical integration purposes, but let's not get ahead of ourselves ;-)

## 4 - f ##

The *f* script is in fact a simple wrapper to ipcheck.pl, which I install as `/usr/local/bin/f` so that it's in the default search path. This script alone is what users will see as the *f* script. The command that users run as *f* is in fact this:

    #!/bin/sh
    /path_to_the_actual_perl_code/ipcheck.pl $@

## Status Check ##

Run `f -v` to check the contributing data sources and the last update of the data files. e.g.

    [john@atlhost ]$ f -v
    
           This Program: f (ipcheck.pl), v1.1.1 - December 15, 2014
                 Author: John Herbert
    
        Data Extraction: ipgrabber.pl
             Conversion: ip2bin.pl
    
     Total # IP entries: 44360
         IP Data Source: ATL ( 8173) at Tue Jan 14 20:05:18 2014 UTC
         IP Data Source: YYZ (32651) at Wed Jan 15 18:22:07 2014 UTC
         IP Data Source: MAN (  520) at Wed Jan 15 18:22:07 2014 UTC
         IP Data Source: SFO ( 3016) at Tue Jan 14 19:59:02 2014 UTC


## File Locations ##

Currently, at least:

    Configuration Archives - /data/network/
    Data Files             - /data/fdb/
    Manual Additions       - /data/fdb/manual/
    f wrapper              - /usr/local/bin/f
    ipcheck.pl             - /path_to_the_actual_perl_code/ipcheck.pl
    ip2bin.pl              - /path_to_the_actual_perl_code/ip2bin.pl
    ipgrabber.pl           - /path_to_the_actual_perl_code/ipgrabber.pl


## Configuration File Naming ##

The f tool is not smart enough to auto-detect what kind of file it's reading. Perhaps it could be, but for now it requires that the configuration file name gives it a clue of some sort. For example:

- myrouter1.junos.set == Junos
- myswitch1.cisco.log == Cisco
- myfirewall.screenos == Netscreen

These can be edited to your convenience, but it's how they are right now.



I think that's enough for now.

