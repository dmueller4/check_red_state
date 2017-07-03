#!/usr/bin/perl -w
#vim:et:sw=3
# ---

=head1 NAME

check_utm_red_state - Nagios plugin for checking Sophos RED Device state

=head1 SYNOPSIS

 check_utm_red_state -H Host -R Red ID [-P Port] [-t] [-c] [-v] \

 check_utm_red_state [-h|-V]

=head1 OPTIONS

=over 4

=item -H|--hostl=IP address or hostname

The IP address or hostname where the red device connects to, e.g. 192.168.0.1 or fw.domain.net

=item -R|--red=red ID

The Red ID which should be checked

=item -P|--port=value (default: 22)

sets an alternative port 

=item -t|--timeout=value (default: 10)

sets the timeout for this check, by default 10.

=item -c|--StrictHostKeyChecking={yes;no} (default: no)

Use strict host key check for the connection

=item -v|--verbose

increases verbosity, specify twice to see the original output.

=item -V|--version

print version an exit

=item -h|--help

print help message and exit

INFO

You need to gennerate a key pair for the nagios user in order to use the passwordless authentication with the host. 
This can be done by running ssh-keygen -t rsa -N "" as nagios user or su - nagios -c 'ssh-keygen -t rsa -N "" '.
The public key needs to configured on the firewall for the loginuser.

 UTM <  version 8: the key must be manually add to the authorized_keys file
 UTM >= version 8: the key can be set in the webinterface
 
 !! For UTM >= 9.2 a new perl module must be installed !!
 On Debian install libjson-perl and libjson-xs-perl

=back

=cut

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../perl/lib";
use Nagios::Plugin;
use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
use Storable;
use Time::Local;
use POSIX qw/floor/;

my $name = "RED STATE";
my $np = Nagios::Plugin->new( shortname => $name);
my $host = '';
my $host_port = 22;
my $tmpdir = '/tmp';
my $cmd_scp = '';
my $cmd_rpath = 'tmp';
my $use_scp_option_StrictHostKeyChecking = 'no';
my $cmd_get_version = '';
my $line = '';
my $line_time = "";
my $line_date = "";

my $red_id = '';
my $red_ip = '';
my $red_uptime = '';
my @red_connected_since = '';
my $red_connected_since_min = 0;
my $red_status = '';
my $red_uplink = '';
my $red_lping = '';
my $red_signal_strength = '';
my $red_linkstate = '';

my $result = UNKNOWN;
my $version = 'V1.1j/2017-03-07/dm';
my $printversion = 0;
my $verbose = 0;
my $help = 0;
my $timeout = 10;
my $debug = 0;
my $uptime = "";
my $error = 0;

# -- GetOpt
GetOptions(
   "H|host=s"       => \$host,
   "R|red=s"        => \$red_id,
   "P|port=s"       => \$host_port,
   "t|timeout=s"    => \$timeout,
   "c|StrictHostKeyChecking=s" => \$use_scp_option_StrictHostKeyChecking,
   "h|help"         => \$help,
   "V|version"      => \$printversion,
   "v|verbose+"     => \$verbose,
   "d|debug+"       => \$debug,
) or pod2usage({ -exitval => UNKNOWN,
                 -verbose => 0,
                 -msg     => "*** unknown argument found ***" });

pod2usage(-verbose => 1,
          -exitval => UNKNOWN,
     -output  => \*STDOUT,
         ) if ( $help );

pod2usage(-msg     => "\n$0 -- version: $version\n",
          -verbose => 0,
          -exitval => UNKNOWN,
         ) if ( $printversion );

pod2usage(-msg     => "*** no host/RED ID specified ***",
          -verbose => 0,
          -exitval => UNKNOWN,
         ) unless $red_id;
if ($debug) { $verbose++} # if debug sete verbose to

# -- Alarm
$SIG{ALRM} = sub { $np->nagios_die("Timeout reached"); }; 
alarm($timeout);

# -- Test if executable are available
unless (-f "/usr/bin/stat") {
    print "Error program stat not found in path: /usr/bin/stat \n"; $error++;
}
print "> found programm stat \n" if ($debug);
unless (-f "/usr/bin/scp") {
    print "Error program scp not found in path: /usr/bin/scp \n";$error++;
}
print "> found programm scp \n" if ($debug);
unless (-f "/usr/bin/ssh") {
    print "Error program ssh not found in path: /usr/bin/ssh \n";$error++;
}
print "> found programm ssh \n" if ($debug);
unless (-f "/bin/ls") {
    print "Error program ls not found in path: /bin/ls \n";$error++;
}
print "> found programm ls \n" if ($debug);
if ($error > 0) { exit(1); }

# -- main

$host = $1 if ($host && $host =~ m/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-zA-Z][-a-zA-Z0-9]+(\.[a-zA-Z][-a-zA-Z0-9]+)*)$/);
unless ($host) {
   print "No target host specified\n";
   $np->nagios_exit( CRITICAL, "Failure in hostname or IP");
}

# -- check asg/utm version
$cmd_get_version = `ssh -q -o StrictHostKeyChecking=$use_scp_option_StrictHostKeyChecking -p $host_port loginuser\@$host cat /etc/version`;
if (length($cmd_get_version) eq 0) {
    print " connect to firewall ($host) failed \n";
    print " check if ssh key is in place in both systems\n" if ($verbose);
    print "error: ",`ssh  -o StrictHostKeyChecking=$use_scp_option_StrictHostKeyChecking -p $host_port loginuser\@$host cat /etc/version 2>&1` if ($verbose);
    $np->nagios_exit( CRITICAL, "Failed to connect to host");
}
print " connect to firewall ($host) successful \n" if ($verbose);
if ($cmd_get_version > 9.1) {
	$cmd_rpath = 'tmp/red/server';
}
print " detected UTM version: $cmd_get_version\n" if ($verbose);

$cmd_scp = `LANG=C scp -p -o StrictHostKeyChecking=$use_scp_option_StrictHostKeyChecking -P $host_port loginuser\@$host:/var/sec/chroot-httpd/$cmd_rpath/red_state_$red_id $tmpdir/ 2>&1 `;
print "> get command return state: $cmd_scp \n" if ($debug>1);
print "> collect data command return:" if ($debug);
print " OK \n" if ($debug and length($cmd_scp) =~0);

if (length($cmd_scp) =~ 0 or $cmd_scp =~ /Warning: Permanently added/ or $cmd_scp =~ /WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!/ ) {
   print " Tolerated  - check Warnings in SSH connection \n" if ($debug and length($cmd_scp) !~0);
   print " collect data from ($host) successful \n" if ($verbose);
   $line = `ls -l $tmpdir/red_state_$red_id --time-style=long-iso 2>&1`;
   ($line_time) = $line =~ /([0-9]{2}:[0-9]{2})/;
   ($line_date) = $line =~ /([0-9]{4}-[0-9]{2}-[0-9]{2})/;
   print " file info $tmpdir/red_state_$red_id  time: $line_time  date: $line_date\n" if ($verbose);
   print "> line: $line " if ($debug >1);
   print "> file found .." if ($debug); 
   if (($line !~ /cannot access/i) and ($line !~ /No such file or directory/i)) { # file found
      print " OK \n> file size .." if ($debug); 
      if (`LANG=C stat  $tmpdir/red_state_$red_id --format="\%s"` !~ /^0/i) { # file size ok
         print "OK \n" if ($debug);
         if ($cmd_get_version < 9.2) {
             my $hashref;
             $hashref = retrieve("$tmpdir/red_state_$red_id");
             $red_ip = $hashref->{'peer'};
             $red_status = $hashref->{'status'};
             $red_uplink = $hashref->{'uplink'};

             $red_lping = localtime($hashref->{'lastping'});
         } elsif ($cmd_get_version > 9.2) {
             use JSON;
             my $json;
             {
               local $/; #Enable 'slurp' mode
               open my $fh, "<", "$tmpdir/red_state_$red_id";
               $json = <$fh>;
               close $fh;
             }
             my $data = decode_json($json);
             $red_ip = $data->{'peer'};
             $red_status = $data->{'status'};
             $red_uplink = $data->{'uplink'};
             $red_linkstate = $data->{'linkstate'};
             $red_signal_strength = $data->{'signal_strength'};

             $red_lping = localtime($data->{'lastping'});
         }
         if (length($red_uplink) eq 0) {
             $red_uplink = "#";
         }
         print " RED info: local interface $red_uplink, remote IP $red_ip, last contact was $red_lping\n" if ($verbose);
         if ($red_linkstate or ($red_signal_strength !~ /N\/A/))  {
            print " Link state: $red_linkstate, WIFI signal strength: $red_signal_strength \n" if ($debug);
         }
         `rm -rf $tmpdir/red_state_$red_id`;
         
        if ($red_status eq "online") {
            $result = OK;
            $np->add_perfdata( label => "Uptime", value => getREDuptime(), uom => "min" );
            print " perfdata: Uptime ", getREDuptime(),"min \n" if ($verbose);
        } elsif ($red_status eq 0) { # offline
            $result = CRITICAL;
            $np->nagios_exit( CRITICAL, "unable to connect to RED - offline since $uptime");
        } elsif ($red_status eq "offline") {
            my $red_oldip = $red_ip;
            $red_ip = '';
            # adv. tests 
            # RED_ID,RED_IP =  ps ax | grep A310xx | grep -v "grep" | grep -Eo '([A-Z0-9]{10,15})|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            $red_ip = `ssh -q -o StrictHostKeyChecking=$use_scp_option_StrictHostKeyChecking -p $host_port loginuser\@$host ps ax | grep $red_id | grep -Eo '([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})'`;
            if ($red_ip =~ m/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-zA-Z][-a-zA-Z0-9]+(\.[a-zA-Z][-a-zA-Z0-9]+)*)$/) {
                $result = OK;
                $np->add_perfdata( label => "Uptime", value => getREDuptime(), uom => "min" );
            } else {
                $result = CRITICAL;
                if ($red_oldip) {
                    $np->nagios_exit( CRITICAL, "unable to connect to RED, last IP $red_oldip - offline");
                }else {
                    $np->nagios_exit( CRITICAL, "unable to connect to RED - offline");
                }
                
            }
        }
      } else { # offline
        print " ERROR - size is zero; empty file \n" if ($debug); 
        `rm -rf $tmpdir/red_state_$red_id`;
        $np->nagios_exit( CRITICAL, "unable to connect to RED - offline since $uptime");
      }
   } else { # no access or file not found on local machine
       print " ERROR - no access or file not found on local machine \n" if ($debug); 
   }
} else {
   if (length($cmd_scp) > 0) {
      print " ERROR - RED ID not found \n" if ($verbose); 
      $np->nagios_exit( CRITICAL, "data collection for RED ID failed, file not found");
   }
   $np->nagios_exit( CRITICAL, "unable to connect to firewall");
}

alarm(0);

$np->nagios_exit( $result, "RED connected to $red_uplink from $red_ip, last contact was $red_lping");

sub getREDuptime {
    my @red_time = '';
    my @red_time_day  = '';
    $red_uptime = `ssh -q -o StrictHostKeyChecking=$use_scp_option_StrictHostKeyChecking -p $host_port loginuser\@$host ps axo '%p%t%a' | grep $red_id | grep -Eo '([0-9]{0,2}-?[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2})'`;
    if ($red_uptime =~ /-/) {
        @red_time_day = split(/-/,$red_uptime);
        @red_time = split(/:/,$red_time_day[1]);
        if ($red_time_day[0] gt 0) {
            $red_time[0] += $red_time_day[0]*24;
        }
    } else {
        @red_time = split(/:/,$red_uptime);
    }
    if (length($red_uptime) gt 0 and $red_time[0] gt 0 ) {
        $red_time[1] += $red_time[0]*60;
    } else {
        $red_time[1] = 0;
    }
    return $red_time[1];
}

=head1 AUTHOR

daniel.mueller (at) cobotec (dot) de

=head1 KNOWN ISSUES

may be

=head1 BUGS

may be

=head1 LICENSE

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License (and no
later version).

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

=head1 HISTORY

V1.1j/2017-03-07 better error handling, tested with 9.5
V1.1i/2015-13-09 bugfix release, more connection error handling
V1.1h/2014-23-08 first prtg fork
V1.1g/2014-25-03 update release, supports now version 9.2, perl json module required
V1.1f/2014-02-01 fixed uptime calculation and some bugs, tested with version 9.106-17
V1.1e/2013-11-11 added adv checks for red online state; apadted changes on red config
V1.1d/2013-30-09 added option to change ssh port
V1.1c/2013-07-08 bugifx release, after update to version 9.103-5 installation offline reds were shown as online
V1.1b/2013-27-05 update release, supports now version 9.1
V1.1a/2012-27-01 bugfix release, offline RED not correct identified
V1.1/2011-30-08 minor bugfixes, changed default value for StrictHostKeyChecking to no
V1.0/2011-01-06 inital version

=cut
