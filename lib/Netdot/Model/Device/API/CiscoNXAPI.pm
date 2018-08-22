package Netdot::Model::Device::API::CiscoNXAPI;

use base 'Netdot::Model::Device::API';
use warnings;
#use strict;
use Net::Appliance::Session;

my $logger = Netdot->log->get_logger('Netdot::Model::Device');

# Some regular expressions
my $IPV4 = Netdot->get_ipv4_regex();
my $IPV6 = Netdot->get_ipv6_regex();
my $CISCO_MAC = '\w{4}\.\w{4}\.\w{4}';

=head1 NAME

Netdot::Model::Device::API::CiscoNXOS - Cisco NXOS Class

=head1 SYNOPSIS

 Overrides certain methods from the Device class. More Specifically, methods in
 this class try to obtain forwarding tables and ARP/ND caches via CLI
 instead of via SNMP.

=head1 INSTANCE METHODS
=cut

############################################################################

=head2 get_arp - Fetch ARP tables

  Arguments:
    session - SNMP session (optional)
  Returns:
    Hashref
  Examples:
    my $cache = $self->get_arp(%args)
=cut

sub get_arp {
    my ($self, %argv) = @_;
    $self->isa_object_method('get_arp');
    my $host = $self->fqdn;

    unless ( $self->collect_arp ){
	$logger->debug(sub{"Device::CiscoIOS::_get_arp: $host excluded from ARP collection. Skipping"});
	return;
    }
    if ( $self->is_in_downtime ){
	$logger->debug(sub{"Device::CiscoIOS::_get_arp: $host in downtime. Skipping"});
	return;
    }

    # This will hold both ARP and v6 ND caches
    my %cache;

    ### v4 ARP
    my $start = time;
    my $arp_count = 0;
    my $arp_cache = $self->_get_arp_from_api(host=>$host) ||
	$self->_get_arp_from_snmp(session=>$argv{session});

    $logger->info(sub{ "Arp Cache $arp_cache "});
    foreach ( keys %$arp_cache ){
	$cache{'4'}{$_} = $arp_cache->{$_};
	$arp_count+= scalar(keys %{$arp_cache->{$_}})
    }
    my $end = time;
    $logger->info(sub{ sprintf("$host: ARP cache fetched. %s entries in %s",
			       $arp_count, $self->sec2dhms($end-$start) ) });


    if ( $self->config->get('GET_IPV6_ND') ){
	### v6 ND
	$start = time;
	my $nd_count = 0;
	my $nd_cache  = $self->_get_v6_nd_from_api(host=>$host) ||
	    $self->_get_v6_nd_from_snmp($argv{session});
	# Here we have to go one level deeper in order to
	# avoid losing the previous entries
	foreach ( keys %$nd_cache ){
	    foreach my $ip ( keys %{$nd_cache->{$_}} ){
		$cache{'6'}{$_}{$ip} = $nd_cache->{$_}->{$ip};
		$nd_count++;
	    }
	}
	$end = time;
	$logger->info(sub{ sprintf("$host: IPv6 ND cache fetched. %s entries in %s",
				   $nd_count, $self->sec2dhms($end-$start) ) });
    }

    return \%cache;
}

############################################################################

=head2 get_fwt - Fetch forwarding tables

  Arguments:
    session - SNMP session (optional)
  Returns:
    Hashref
  Examples:
    my $fwt = $self->get_fwt(%args)
=cut

sub get_fwt {
    my ($self, %argv) = @_;
    $self->isa_object_method('get_fwt');
    my $host = $self->fqdn;
    my $fwt = {};

    unless ( $self->collect_fwt ){
	$logger->debug(sub{"Device::API::CiscoNXOS::get_fwt: $host excluded from FWT collection. Skipping"});
	return;
    }
    if ( $self->is_in_downtime ){
	$logger->debug(sub{"Device::API::CiscoNXOS::get_fwt: $host in downtime. Skipping"});
	return;
    }

    my $start     = time;
    my $fwt_count = 0;

    # Try CLI, and then SNMP
    $fwt = $self->_get_fwt_from_api(host=>$host) ||
	$self->_get_fwt_from_snmp(session=>$argv{session});

    map { $fwt_count+= scalar(keys %{$fwt->{$_}}) } keys %$fwt;
    my $end = time;
    $logger->debug(sub{ sprintf("$host: FWT fetched. %s entries in %s",
				$fwt_count, $self->sec2dhms($end-$start) ) });
   return $fwt;

}


############################################################################
#_get_arp_from_api - Fetch ARP tables via API
#
#   Arguments:
#     host
#   Returns:
#     Hash ref.
#   Examples:
#     $self->_get_arp_from_cli(host=>'foo');
#
sub _get_arp_from_api {
    my ($self, %argv) = @_;
    $self->isa_object_method('_get_arp_from_api');

    my $host = $argv{host};
    my $args = $self->_get_credentials(host=>$host);
    return unless ref($args) eq 'HASH';

    my @output = $self->_api_cmd(%$args, host=>$host, cmd=>'show ip arp vrf all');

    my %cache;
    shift @output; # Ignore header line
    # Address         Age       MAC Address     Interface       Flags
    # 10.0.128.200    00:01:02  0025.90e6.6c3c  mgmt0
    # 10.0.129.21     00:13:22  d050.9942.e5a7  mgmt0
    foreach my $line ( @output ) {
	my ($iname, $ip, $mac, $intid);
	chomp($line);
	    $logger->debug(sub{"Device::API::CiscoNXOS::_get_arp_from_cli: Line: $line" });
	    if ( $line =~ /^($IPV4)\s+[-\d:]+\s+($CISCO_MAC)\s+(\S+)/o ) {
	    $ip    = $1;
	    $mac   = $2;
	    $iname = $3;
	}else{
	    $logger->debug(sub{"Device::CLI::CiscoNXOS::_get_arp_from_cli: line did not match criteria: $line" });
	    next;
	}
	unless ( $ip && $mac && $iname ){
	    $logger->debug(sub{"Device::CiscoNXOS::_get_arp_from_cli: Missing information: $line" });
	    next;
	}
	$cache{$iname}{$ip} = $mac;
    }
    return $self->_validate_arp(\%cache, 4);
}

############################################################################
#_get_v6_nd_from_api - Fetch ARP tables via NXAPI
#
#   Arguments:
#     host
#   Returns:
#     Hash ref.
#   Examples:
#     $self->_get_v6_nd_from_cli(host=>'foo');
#
sub _get_v6_nd_from_api {
    my ($self, %argv) = @_;
    $self->isa_object_method('_get_v6_nd_from_api');

    my $host = $argv{host};
    my $args = $self->_get_credentials(host=>$host);
    return unless ref($args) eq 'HASH';

    my @output = $self->_api_cmd(%$args, host=>$host, cmd=>'show ipv6 neighbor vrf all');
    shift @output; # Ignore header line
    my %cache;
    foreach my $line ( @output ) {
	my ($ip, $mac, $iname);
	chomp($line);
	# Lines look like this:
	# FE80::219:E200:3B7:1920                     0 0019.e2b7.1920  REACH Gi0/2.3
	if ( $line =~ /^($IPV6)\s+[-\d:]+\s+($CISCO_MAC)\s+\S+\s+(\S+)/o ) {
	    $ip    = $1;
	    $mac   = $2;
	    $iname = $3;
	}else{
	    $logger->debug(sub{"Device::API::CiscoNXOS::_get_v6_nd_from_cli: line did not match criteria: $line" });
	    next;
	}
	unless ( $iname && $ip && $mac ){
	    $logger->debug(sub{"Device::API::CiscoNXOS::_get_v6_nd_from_cli: Missing information: $line"});
	    next;
	}
	$cache{$iname}{$ip} = $mac;
    }
    return $self->_validate_arp(\%cache, 6);
}

############################################################################
#_get_fwt_from_api - Fetch forwarding tables via NXAPI
#
#
#   Arguments:
#     host
#   Returns:
#     Hash ref.
#
#   Examples:
#     $self->_get_fwt_from_cli();
#
#
sub _get_fwt_from_api {
    my ($self, %argv) = @_;
    $self->isa_object_method('_get_fwt_from_api');

    my $host = $argv{host};
    my $args = $self->_get_credentials(host=>$host);
    return unless ref($args) eq 'HASH';

    my @output = $self->_api_cmd(%$args, host=>$host, cmd=>'show mac address-table dynamic');

    # MAP interface names to IDs
    my %int_names;
    foreach my $int ( $self->interfaces ){
	my $name = $self->_reduce_iname($int->name);
	$int_names{$name} = $int->id;
    }


    my ($iname, $mac, $intid);
    my %fwt;

    # Output looks like this:
    #	Legend:
    #		* - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC
    #		age - seconds since last seen,+ - primary entry using vPC Peer-Link,
    #		(T) - True, (F) - False, C - ControlPlane MAC
    #	   VLAN     MAC Address      Type      age     Secure NTFY Ports
    #	---------+-----------------+--------+---------+------+----+------------------
    #	*   10     0006.f674.9a40   dynamic  0         F      F    Po4
    #	*   10     0025.90cf.0ec6   dynamic  0         F      F    Po10
    #	+   10     0025.90e2.c0cc   dynamic  0         F      F    Po10
    #


    foreach my $line ( @output ) {
	chomp($line);
	if ( $line =~ /^[*\s\+]\s+\S+\s+($CISCO_MAC)\s+dynamic\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$/o ) {
	    $mac   = $1;
	    $iname = $2;
	}else{
	    $logger->debug(sub{"Device::API::CiscoNXO::_get_fwt_from_api: ".
				   "line did not match criteria: '$line'" });
	    next;
	}
	$iname = $self->_reduce_iname($iname);
	my $intid = $int_names{$iname};

	unless ( $intid ) {
	    $logger->warn("Device::API::CiscoNXOS::_get_fwt_from_api: $host: ".
			  "Could not match $iname to any interface names");
	    next;
	}
	eval {
	    $mac = PhysAddr->validate($mac);
	};
	if ( my $e = $@ ){
	    $logger->debug(sub{"Device::API::CiscoNXOS::_get_fwt_from_api: ".
				   "$host: Invalid MAC: $e" });
	    next;
	}
	# Store in hash
	$fwt{$intid}{$mac} = 1;
	$logger->debug(sub{"Device::API::CiscoNXOS::_get_fwt_from_api: ".
			       "$host: $iname -> $mac" });
    }

    return \%fwt;
}

############################################################################
# _reduce_iname
#  Convert "GigabitEthernet0/3 into "Gi0/3" to match the different formats
#
# Arguments:
#   string
# Returns:
#   string
#
sub _reduce_iname{
    my ($self, $name) = @_;
    return unless $name;
    $name =~ s/^(\w{2})\S*?([\d\/]+).*/$1$2/;

    # Port channels have a lowercase p in netdot but here use Po1, make it lowercase
    if ( $name =~ /^Po\d+$/o ) {
        $name =~ s/^(\w{2})\S*?([\d\/]+).*/\l$1$2/;
    }

    return $name;
}

=head1 AUTHOR

Carlos Vicente, C<< <cvicente at ns.uoregon.edu> >>

=head1 COPYRIGHT & LICENSE

Copyright 2011 University of Oregon, all rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=cut

#Be sure to return 1
1;
