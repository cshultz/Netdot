package Netdot::Model::Device::CiscoIOS;

use base 'Netdot::Model::Device';
use warnings;
use strict;
use Net::Appliance::Session;

my $logger = Netdot->log->get_logger('Netdot::Model::Device');

=head1 NAME

Netdot::Model::Device::CiscoIOS - Cisco IOS Class

=head1 SYNOPSIS

 Overrides certain methods from the Device class

=head1 CLASS METHODS
=cut

=head1 INSTANCE METHODS
=cut

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
    my $cache = {};

    unless ( $self->collect_arp ){
	$logger->debug(sub{"Device::CiscoIOS::_get_arp: $host excluded from ARP collection. Skipping"});
	return;
    }
    if ( $self->is_in_downtime ){
	$logger->debug(sub{"Device::CiscoIOS::_get_arp: $host in downtime. Skipping"});
	return;
    }

    my $start     = time;
    my $arp_count = 0;

    # Try CLI, and then SNMP 
    $cache = $self->_get_arp_from_cli(host=>$host) ||
	$self->_get_arp_from_snmp(session=>$argv{session});

    map { $arp_count+= scalar(keys %{$cache->{$_}}) } keys %$cache;
    my $end = time;
    $logger->debug(sub{ sprintf("$host: ARP cache fetched. %s entries in %s", 
				$arp_count, $self->sec2dhms($end-$start) ) });
   return $cache;

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
	$logger->debug(sub{"Device::CiscoIOS::get_fwt: $host excluded from FWT collection. Skipping"});
	return;
    }
    if ( $self->is_in_downtime ){
	$logger->debug(sub{"Device::CiscoIOS::get_fwt: $host in downtime. Skipping"});
	return;
    }

    my $start     = time;
    my $fwt_count = 0;
    
    # Try CLI, and then SNMP 
    $fwt = $self->_get_fwt_from_cli(host=>$host) ||
	$self->_get_fwt_from_snmp(session=>$argv{session});

    map { $fwt_count+= scalar(keys %{$fwt->{$_}}) } keys %$fwt;
    my $end = time;
    $logger->debug(sub{ sprintf("$host: FWT fetched. %s entries in %s", 
				$fwt_count, $self->sec2dhms($end-$start) ) });
   return $fwt;

}


############################################################################
#_get_arp_from_cli - Fetch ARP tables via CLI
#
#    
#   Arguments:
#     host
#   Returns:
#     Hash ref.
#   Examples:
#     $self->_get_arp_from_cli();
#
#
sub _get_arp_from_cli {
    my ($self, %argv) = @_;
    $self->isa_object_method('_get_arp_from_cli');

    my $host = $argv{host};
    my $args = $self->_get_credentials(host=>$host);
    return unless ref($args) eq 'HASH';

    my @output = $self->_cli_cmd(%$args, host=>$host, cmd=>'show ip arp');

    # MAP interface names to IDs
    # Get all interface IPs for subnet validation
    my %int_names;
    my %devsubnets;
    foreach my $int ( $self->interfaces ){
	$int_names{$int->name} = $int->id;
	foreach my $ip ( $int->ips ){
	    push @{$devsubnets{$int->id}}, $ip->parent->_netaddr 
		if $ip->parent;
	}
    }

    my %cache;
    my ($iname, $ip, $mac, $intid);
    shift @output; # Ignore header line
    foreach my $line ( @output ) {
	chomp($line);
	if ( $line =~ /^Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+[-\d]+\s+(\w{4}\.\w{4}\.\w{4})\s+ARPA\s+(\S+)/ ) {
	    $ip    = $1;
	    $mac   = $2;
	    $iname = $3;
	}else{
	    $logger->debug(sub{"Device::CiscoIOS::_get_arp_from_cli: line did not match criteria: $line" });
	    next;
	}

	my $intid = $int_names{$iname};

	unless ( $intid ) {
	    $logger->warn("Device::CiscoIOS::_get_arp_from_cli: $host: Could not match $iname to any interface name");
	    next;
	}
	
	my $validmac = PhysAddr->validate($mac); 
	if ( $validmac ){
	    $mac = $validmac;
	}else{
	    $logger->debug(sub{"Device::CiscoIOS::_get_arp_from_cli: $host: Invalid MAC: $mac" });
	    next;
	}	

	if ( Netdot->config->get('IGNORE_IPS_FROM_ARP_NOT_WITHIN_SUBNET') ){
	    # Don't accept entry if ip is not within this interface's subnets
	    my $invalid_subnet = 1;
	    foreach my $nsub ( @{$devsubnets{$intid}} ){
		my $nip = NetAddr::IP->new($ip) 
		    || $self->throw_fatal(sprintf("Cannot create NetAddr::IP object from %s", $ip));
		if ( $nip->within($nsub) ){
		    $invalid_subnet = 0;
		    last;
		}else{
		    $logger->debug(sub{sprintf("Device::CiscoIOS::_get_arp_from_cli: $host: IP $ip not within %s", 
					       $nsub->cidr)});
		}
	    }
	    if ( $invalid_subnet ){
		$logger->debug(sub{"Device::CiscoIOS::_get_arp_from_cli: $host: IP $ip not within interface $iname subnets"});
		next;
	    }
	}

	# Store in hash
	$cache{$intid}{$ip} = $mac;
	$logger->debug(sub{"Device::CiscoIOS::_get_arp_from_cli: $host: $iname -> $ip -> $mac" });
    }
    
    return \%cache;
}



############################################################################
#_get_fwt_from_cli - Fetch forwarding tables via CLI
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
sub _get_fwt_from_cli {
    my ($self, %argv) = @_;
    $self->isa_object_method('_get_fwt_from_cli');

    my $host = $argv{host};
    my $args = $self->_get_credentials(host=>$host);
    return unless ref($args) eq 'HASH';

    my @output = $self->_cli_cmd(%$args, host=>$host, cmd=>'show mac-address-table dynamic');

    # MAP interface names to IDs
    my %int_names;
    foreach my $int ( $self->interfaces ){
	my $name = $int->name;
	# Shorten names to match output
	# i.e GigabitEthernet1/2 -> Gi1/2
	$name =~ s/^([a-z]{2}).+?([\d\/]+)$/$1$2/i;
	$int_names{$name} = $int->id;
    }
    

    my ($iname, $mac, $intid);
    my %fwt;
    
    # Output look like this:
    #  vlan   mac address     type    learn     age              ports
    # ------+----------------+--------+-----+----------+--------------------------
    #   128  0024.b20e.fe0f   dynamic  Yes        255   Gi9/22

    foreach my $line ( @output ) {
	chomp($line);
	if ( $line =~ /^\*?\s+.*\s+(\w{4}\.\w{4}\.\w{4})\s+dynamic\s+\S+\s+\S+\s+(\S+)\s+$/ ) {
	    $mac   = $1;
	    $iname = $2;
	}else{
	    $logger->debug(sub{"Device::CiscoIOS::_get_fwt_from_cli: line did not match criteria: $line" });
	    next;
	}

	my $intid = $int_names{$iname};

	unless ( $intid ) {
	    $logger->warn("Device::CiscoIOS::_get_fwt_from_cli: $host: Could not match $iname to any interface names");
	    next;
	}
	
	my $validmac = PhysAddr->validate($mac);
	if ( $validmac ){
	    $mac = $validmac;
	}else{
	    $logger->debug(sub{"Device::CiscoIOS::_get_fwt_from_cli: $host: Invalid MAC: $mac" });
	    next;
	}	

	# Store in hash
	$fwt{$intid}{$mac} = 1;
	$logger->debug(sub{"Device::CiscoIOS::_get_fwt_from_cli: $host: $iname -> $mac" });
    }
    
    return \%fwt;
}


############################################################################
# Get CLI login credentials from config file
#
# Arguments: 
#   host
# Returns:
#   hashref
#
sub _get_credentials {
    my ($self, %argv) = @_;

    my $config_item = 'DEVICE_CLI_CREDENTIALS';
    my $host = $argv{host};
    my $cli_cred_conf = Netdot->config->get($config_item);
    unless ( ref($cli_cred_conf) eq 'ARRAY' ){
	$self->throw_user("Device::CiscoIOS::_get_credentials: config $config_item must be an array reference.");
    }
    unless ( @$cli_cred_conf ){
	$self->throw_user("Device::CiscoIOS::_get_credentials: config $config_item is empty");
    }

    my $match = 0;
    foreach my $cred ( @$cli_cred_conf ){
	my $pattern = $cred->{pattern};
	if ( $host =~ /$pattern/ ){
	    $match = 1;
	    my %args;
	    $args{login}      = $cred->{login};
	    $args{password}   = $cred->{password};
	    $args{privileged} = $cred->{privileged};
	    $args{transport}  = $cred->{transport} || 'SSH';
	    $args{timeout}    = $cred->{timeout}   || '30';
	    return \%args;
	}
    }   
    if ( !$match ){
	$logger->warn("Device::CiscoIOS::_get_credentials: $host did not match any patterns in configured credentials.");
    }
    return;
}

############################################################################
# Issue CLI command
#
# Arguments: 
#   command
# Returns:
#   array
#
sub _cli_cmd {
    my ($self, %argv) = @_;
    my ($login, $password, $privileged, $transport, $timeout, $host, $cmd) = 
	@argv{'login', 'password', 'privileged', 'transport', 'timeout', 'host', 'cmd'};
    
    $self->throw_user("Device::CiscoIOS::_cli_cmd: $host: Missing required parameters: login/password")
	unless ( $login && $password && $cmd );
    
    my @output;
    eval {
	$logger->debug(sub{"$host: issuing CLI command: '$cmd' over $transport"});
	my $s = Net::Appliance::Session->new(
	    Host      => $host,
	    Transport => $transport,
	    );
	
	$s->do_paging(0);
	
	$s->connect(Name      => $login, 
		    Password  => $password,
		    SHKC      => 0,
		    Opts      => [
			'-o', "ConnectTimeout $timeout",
			'-o', 'CheckHostIP no',
			'-o', 'StrictHostKeyChecking no',
		    ],
	    );
	
	if ( $privileged ){
	    $s->begin_privileged($privileged);
	}
	$s->cmd('terminal length 0');
	@output = $s->cmd(string=>$cmd, timeout=>$timeout);
	$s->cmd('terminal length 36');

	if ( $privileged ){
	    $s->end_privileged;
	}
	$s->close;
    };
    if ( my $e = $@ ){
	$self->throw_user("Device::CiscoIOS::_get_arp_from_cli: $host: $e");
    }
    return @output;
}