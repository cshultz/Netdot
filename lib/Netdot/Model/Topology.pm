package Netdot::Model::Topology;

use base 'Netdot::Model';
use warnings;
use strict;

my $logger = Netdot->log->get_logger('Netdot::Model::Device');
my $MAC  = Netdot->get_mac_regex();
my $IP   = Netdot->get_ipv4_regex();



# Make sure to return 1
1;

=head1 NAME

Netdot::Model::Topology

=head1 SYNOPSIS

Netdot Device Topology Class

=head1 CLASS METHODS
=cut

######################################################################################
=head2 discover - Discover Topology for devices within (optional) given IP block

  Kinds of IP blocks allowed: 'Container' and 'Subnet'
        
  Arguments:
    Hash with following keys:
    blocks - array ref of CIDR blocks (192.168.0.0/24)
  Returns:
    
  Examples:
    Netdot::Model::Topology->discover(blocks=>['192.1.0.0/16', ...]);

=cut
sub discover {
    my ($class, %argv) = @_;
    $class->isa_class_method('discover');

    my @blocks = (exists $argv{blocks}) ? @{$argv{blocks}}  : ();
    my $blist = (@blocks) ? join ', ', @blocks : "DB";

    my %SOURCES;
    $SOURCES{DP}  = 1 if $class->config->get('TOPO_USE_DP');
    $SOURCES{STP} = 1 if $class->config->get('TOPO_USE_STP');
    $SOURCES{FDB} = 1 if $class->config->get('TOPO_USE_FDB');
    my $MINSCORE  = $class->config->get('TOPO_MIN_SCORE');
    my $srcs = join ', ', keys %SOURCES;
    
    my %devs;
    if (@blocks) {
        foreach my $block ( @blocks ){
            my $ipb = Ipblock->search(address=>$block)->first;
            unless ( $ipb ){
                $class->throw_user("IP block $block not found in DB");
            }
            my $status = $ipb->status->name;
            if (  $status eq 'Container' || $status eq 'Subnet' ){
                map { $devs{$_->id} = $_ } @{$ipb->get_devices()};
            }else{
                $class->throw_user(sprintf("Block %s is %s. Topology discovery only allowed on Container or Subnet Blocks",
                                           $ipb->get_label, $status ));
            }
        }
    } else {
        map { $devs{$_->id} = $_ } Device->retrieve_all;
    }

    $logger->info(sprintf("Discovering topology for devices in %s, using sources: %s. Min score: %s", 
			  $blist, $srcs, $MINSCORE));

    my $start = time;
    my (@dp_devs, %stp_roots, %fdb_vlans);
    my $count = 0;
    foreach my $devid ( keys %devs ){
	my $dev = $devs{$devid};
	# STP sources
	if ( $SOURCES{STP} ){
	    foreach my $stp_instance ( $dev->stp_instances() ){
		if ( my $root = $stp_instance->root_bridge ){
		    $stp_roots{$root}++;
		}
	    }
	}
	# Discovery Protocol sources
	if ( $SOURCES{DP} ){
	    push @dp_devs, $dev;
	}
    }

    # Determine links
    my ($dp_links, $stp_links, $fdb_links);
    foreach my $root ( keys %stp_roots ){
	my $links = $class->get_stp_links(root=>$root);
	map { $stp_links->{$_} = $links->{$_} } keys %$links;
    }

    if (@blocks) {
        $dp_links = $class->get_dp_links(\@dp_devs) if @dp_devs;
        #$fdb_links = $class->get_fdb_links(\@blocks);
        $logger->info("FDB information only gets used on whole-database queries");
    } else {
        $fdb_links = $class->get_fdb_links if ($SOURCES{FDB});
        $dp_links = $class->get_dp_links;
    }   

#    print "Discovering unique things\n";
#    while (my ($from, $to) = each(%$fdb_links)) {
#        if (Interface->retrieve($from)  && Interface->retrieve($to)) {
#            print Interface->retrieve($from)->device->name->name ." -> ".  Interface->retrieve($to)->device->name->name;
#        } else {
#            print "$from -> $to";
#        }
#        print " STP" if (exists $stp_links->{$from} && $stp_links->{$from} == $to);
#        print " DP"  if (exists $dp_links->{$from} && $dp_links->{$from} == $to);
#        print "\n";
#    }

    $logger->debug(sprintf("Netdot::Model::Topology: Links determined in %s", $class->sec2dhms(time - $start)));

    # Get all existing links
    my %old_links;

    # Two approaches - one optimized for dealing with ALL the data
    if (@blocks) {
        foreach my $devid ( keys %devs ){
            my $dev = $devs{$devid};
            my $n   = $dev->get_neighbors();
            map { $old_links{$_} = $n->{$_} } keys %$n;	
        }
    } else {
        my $dbh = $class->db_Main;
        foreach my $row (@{$dbh->selectall_arrayref(
                        "SELECT id, neighbor FROM interface WHERE neighbor != 0")}) {
            my ($id, $neighbor) = @$row;
            $old_links{$id} = $neighbor;
        }
    }

    my %args;
    $args{old_links} = \%old_links;
    $args{dp}        = $dp_links  if $dp_links;
    $args{stp}       = $stp_links if $stp_links;
    $args{fdb}       = $fdb_links if $fdb_links;
    my ($addcount, $remcount) = $class->update_links(%args);
    my $end = time;
    $logger->info(sprintf("Topology discovery on %s done in %s. Links added: %d, removed: %d", 
			  $blist, $class->sec2dhms($end-$start), $addcount, $remcount));
}

######################################################################################
=head2 update_links - Update links between Device Interfaces
    
    The different sources of topology information are assigned specific weights to
    calculate a final score.  Contradicting information lowers the score, while
    corroborating information raises the score in a cumulative fashion.
    Tuples with a score equal or above the configured minimum score are qualified
    to create a link in the database.
    
  Arguments:
    dp        - Hash ref with links discovered by discovery protocols (CDP/LLDP)
    stp       - Hash ref with links discovered by Spanning Tree Protocol
    fdb       - Hash ref with links discovered from forwarding tables
    old_links - Hash ref with current links
  Returns:
    
  Examples:
    Netdot::Model::Topology->update_links(db_links=>$links);

=cut
sub update_links {
    my ($class, %argv) = @_;
    my %links;
    my %WEIGHTS;
    $WEIGHTS{dp}  = $class->config->get('TOPO_WEIGHT_DP');
    $WEIGHTS{stp} = $class->config->get('TOPO_WEIGHT_STP');
    $WEIGHTS{fdb} = $class->config->get('TOPO_WEIGHT_FDB');
    my $MINSCORE  = $class->config->get('TOPO_MIN_SCORE');
    my %hashes;
    my $old_links = $argv{old_links};
    foreach my $source ( qw( dp stp fdb ) ){
	$hashes{$source} = $argv{$source};
    }

    foreach my $source ( keys %hashes ){
	my $score = $WEIGHTS{$source};
	while ( my ($int, $nei) = each %{$hashes{$source}} ){
	    ${$links{$int}{$nei}} += $score;
	    $links{$nei}{$int}     = $links{$int}{$nei};
	    if ( scalar(keys %{$links{$int}}) > 1 ){
		foreach my $o ( keys %{$links{$int}} ){
		    ${$links{$int}{$o}} -= $score if ( $o != $nei );
		}
	    }
	    if ( scalar(keys %{$links{$nei}}) > 1 ){
		foreach my $o ( keys %{$links{$nei}} ){
		    ${$links{$nei}{$o}} -= $score if ( $o != $nei );
		}
	    }
	}
    }
    
    my $addcount = 0;
    my $remcount = 0;
    foreach my $id ( keys %links ){
	foreach my $nei ( keys %{$links{$id}} ){
	    next unless defined $links{$id}{$nei};
	    my $score = ${$links{$id}{$nei}};
	    next unless ( $score >= $MINSCORE );
	    if ( (exists($old_links->{$id})  && $old_links->{$id}  == $nei) || 
		 (exists($old_links->{$nei}) && $old_links->{$nei} == $id) ){
		delete $old_links->{$id}  if ( exists $old_links->{$id}  );
		delete $old_links->{$nei} if ( exists $old_links->{$nei} );
	    }else{
		my $int = Interface->retrieve($id) || $class->throw_fatal("Cannot retrieve Interface id $id");
		eval {
		    $int->add_neighbor(id=>$nei, score=>$score);
		};
		if ( my $e = $@ ){
		    $logger->warn($e);
		}else{
		    $addcount++;
		}
	    }
	    delete $links{$id};
	    delete $links{$nei};		
	}
    }
    # Remove old links than no longer exist
    foreach my $id ( keys %$old_links ){
	my $nei = $old_links->{$id};
	my $int = Interface->retrieve($id) || $class->throw_fatal("Cannot retrieve Interface id $id");
	if ( int($int->neighbor) == $nei ){
	    $int->remove_neighbor() ;
	    $remcount++;
	}
    }
    return ($addcount, $remcount);
}

###################################################################################################
=head2 get_dp_links - Get links between devices based on Discovery Protocol (CDP/LLDP) Info 

  Arguments:  
    Reference to array of Device objects
  Returns:    
    Hashref with link info
  Example:
    my $links = Netdot::Model::Topology->get_dp_links(\@devices);

=cut
sub get_dp_links {
    my ($self, %argv) = @_;
    $self->isa_class_method('get_dp_links');

    # Using raw database access because Class::DBI was too slow here
    my $dbh = $self->db_Main;
    my $results;
    my $sth = $dbh->prepare("SELECT device, id, dp_remote_ip, dp_remote_id, dp_remote_port 
                             FROM interface 
                             WHERE (dp_remote_ip IS NOT NULL OR dp_remote_id IS NOT NULL) 
                               AND dp_remote_port IS NOT NULL");
    $sth->execute;
    $results = $sth->fetchall_arrayref;

    # Filter the results if we didn't want every link in the database
    if (exists $argv{'devs'}) {
        my $devs =  $argv{'devs'};
        my $filteredresults = ();
        my %devicehash;
        foreach my $dev ( @$devs ){
            $devicehash{$dev->id} = $dev;
        }

        foreach my $row (@$results) {
            if (exists $devicehash{$row->[0]}) {
                push @$filteredresults, $row;
            }
        }

        $results = $filteredresults;
    }

    # Now go through everything looking for results
    my %links = ();
    my $allmacs = Device->get_macs_from_all();
    my $allips  = Device->get_ips_from_all();
    my %ips2discover;

    foreach my $row (@$results) {
        my ($did, $iid, $r_ip, $r_id, $r_port) = @$row;
	# In theory this is not needed, but I've seen some funny results from that query
	next unless ( ($r_ip || $r_id) && $r_port );

        next if (exists $links{$iid});

        my $rem_dev = 0;

        # Find the connected device
        if ( $r_ip ) {
            foreach my $rem_ip ( split ',', $r_ip ) {
                my $decimalip = Ipblock->ip2int($rem_ip);
                next unless (exists $allips->{$decimalip});
		$rem_dev = $allips->{$decimalip};
		last if $rem_dev;
		unless ($rem_dev) {
		    $logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Interface id %d: Remote Device IP not found: %s", $iid, $r_ip));
		}
            }
	}
        if ( !$rem_dev && $r_id ) {  
            foreach my $rem_id (split ',', $r_id){
                if ( $rem_id =~ /($MAC)/i ){
                    my $mac = PhysAddr->format_address($1);
                    if ( !exists $allmacs->{$mac} ){
                        $logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Interface id %d: Remote Device MAC not found: %s", $iid, $mac));
			next;
		    }
		    $rem_dev = $allmacs->{$mac};
		}elsif ( $rem_id =~ /($IP)/ ){
		    # Turns out that some devices send IP addresses as IDs
		    my $decimalip = Ipblock->ip2int($1);
		    $rem_dev = $allips->{$decimalip};
		    last if $rem_dev;
		    unless ($rem_dev) {
			$logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Interface id %d: Remote Device IP not found: %s", $iid, $rem_id));
		    }
		}else{
		    # Try to find the device name
		    $rem_dev = Device->search(sysname=>$rem_id)->first 
			|| Device->search(name=>$rem_id)->first;
		    unless ($rem_dev) {
			$logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Interface id %d: Remote Device name not found: %s", $iid, $rem_id));
		    }
		}
		last if $rem_dev;
            }
            unless ( $rem_dev ) {
                $logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Interface id %d: Remote Device not found: %s", $iid, $r_id));
            }
        } 

	unless ( $rem_dev ) {
	    if ( $self->config->get('ADD_UNKNOWN_DP_DEVS') ){
		if ( $r_ip ){
		    foreach my $ip ( split ',', $r_ip ) {
			if ( Ipblock->validate($ip) ){
			    $ips2discover{$ip} = '';
			    $logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Interface id %d: Adding remote device %s to discover list", $iid, $ip));
			}
		    }
		}elsif ( $r_id ){
		    foreach my $rem_id ( split ',', $r_id ) {
			if ( $rem_id =~ /($IP)/ ){
			    my $ip = $1;
			    if ( Ipblock->validate($ip) ){
				$ips2discover{$ip} = '';
				$logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Interface id %d: Adding remote device %s to discover list", $iid, $ip));
			    }
			}
		    }
		}
	    }else{
		my $str = "";
		$str .= "id=$r_id"   if $r_id;
		$str .= ", ip=$r_ip" if $r_ip;
		my $int = Interface->retrieve($iid);
		$logger->warn(sprintf("Netdot::Model::Topology::get_dp_links: %s: Remote Device not found: %s", $int->get_label, $str));
	    }
	    next;
	}

       # Now we have a remote device in $rem_dev
        if ( $r_port ) {
	    my $rem_int;
            foreach my $rem_port ( split ',', $r_port ) {
                # Try name first, then number, then description (if it is unique)
                $rem_int = Interface->search(device=>$rem_dev, name=>$rem_port)->first
		    || Interface->search(device=>$rem_dev, number=>$rem_port)->first;
		unless ( $rem_int ){
		    my @ints = Interface->search(device=>$rem_dev, description=>$rem_port);
		    $rem_int = $ints[0] if ( scalar @ints == 1 );
		}
                if ( $rem_int ){
                    $links{$iid} = $rem_int->id;
                    $links{$rem_int->id} = $iid;
		    $logger->debug(sprintf("Netdot::Model::Topology::get_dp_links: Found link: %d -> %d", 
					   $iid, $rem_int->id));
		    last;
                }
            }
	    unless ( $rem_int ){
		my $int = Interface->retrieve($iid);
		my $dev = ref($rem_dev) ? $rem_dev : Device->retrieve($rem_dev);
		$logger->warn(sprintf("Netdot::Model::Topology::get_dp_links: %s: Port %s not found in Device: %s", 
				      $int->get_label, $r_port, $dev->get_label));
	    }
        }else{
	    my $int = Interface->retrieve($iid);
            $logger->warn(sprintf("Netdot::Model::Topology::get_dp_links: %s: Remote Port not defined", $int->get_label));
        }
    }

    if ( keys %ips2discover ){
	$logger->info("Netdot::Model::Topology::get_dp_links: Discovering unknown neighbors");
	Device->snmp_update_parallel(hosts=>\%ips2discover);
	$logger->info("Netdot::Model::Topology::get_dp_links: You may have to discover topology again to make sure any newly added neighbors are linked");
    }
    return \%links;
}

###################################################################################################
=head2 get_fdb_links - Get links between devices based on FDB information

  Arguments:  
    none
  Returns:    
    Hashref with link info
  Example:
    my $links = Netdot::Model::Topology->get_fdb_links;

=cut
sub get_fdb_links {
    my ($class, %argv) = @_;
    $class->isa_class_method('get_fdb_links');

    my %links;

    my $dbh = $class->db_Main;

    # Find the most recent query for every Vlan
    my $vlanstatement = $dbh->prepare("
        SELECT MAX(tstamp), interfacevlan.vlan
        FROM fwtable, interfacevlan, device, interface
        WHERE fwtable.device = device.id
            AND interface.device = device.id
            AND interfacevlan.interface = interface.id
        GROUP BY interfacevlan.vlan");
    $vlanstatement->execute;

    my ($maxtstamp, $vlan);
    $vlanstatement->bind_columns(\$maxtstamp, \$vlan);

    my $fdbstatement = $dbh->prepare_cached("
            SELECT fwtable.device, interface.id, p1.address, p2.address
            FROM interface, interfacevlan, fwtable, fwtableentry,
                physaddr p1, physaddr p2
            WHERE fwtable.device = interface.device
                AND fwtable.tstamp = ?
                AND fwtableentry.fwtable = fwtable.id
                AND fwtableentry.interface = interface.id
                AND interfacevlan.vlan = ?
                AND interfacevlan.interface = interface.id
                AND interface.physaddr = p1.id
                AND fwtableentry.physaddr = p2.id
        ");

    while ($vlanstatement->fetch) {
        $logger->debug("Discovering how vlan $vlan was connected at $maxtstamp");

        $fdbstatement->execute($maxtstamp, $vlan);
        
        my ($device, $ifaceid, $localiface, $entry);

        $fdbstatement->bind_columns(\$device, \$ifaceid, \$localiface, \$entry);

        my %addriface = ();
        my $d = {};
        while ($fdbstatement->fetch) {
            $addriface{$localiface} = $ifaceid;

            $d->{$device} = {} unless exists $d->{$device};
            $d->{$device}{$localiface} = {} unless exists $d->{$device}{$localiface};
            $d->{$device}{$localiface}{$entry} = 1;
        }

        if (1 >= keys %$d) {
            $logger->debug("Only one device on vlan $vlan");
            next;
        }

        $logger->debug("vlan $vlan has multiple devices at time $maxtstamp");

        # Now thin out the data hash
        my $interfaces = {};
        foreach my $device (keys %$d) {
            foreach my $interface (keys %{$d->{$device}}) {
                $interfaces->{$interface} = 1;
            }
        }

        # Delete all entries that don't refer to other infrastructure
        # devices on the same vlan
        foreach my $device (keys %$d) {
            foreach my $interface (keys %{$d->{$device}}) {
                foreach my $addr (keys %{$d->{$device}{$interface}}) {
                    unless (exists $interfaces->{$addr}) {
                        delete $d->{$device}{$interface}{$addr};
                    }
                }
            }
        }

        # Delete all interfaces that have no fwtable entries for other
        # items in the same vlan
        foreach my $device (keys %$d) {
            foreach my $interface (keys %{$d->{$device}}) {
                if (0 == scalar keys %{$d->{$device}{$interface}}) {
                    delete $d->{$device}{$interface};
                } 
            }
        }

        # Delete all devices on the vlan which don't seem to connect to
        # other devices on the vlan
        foreach my $device (keys %$d) {
            $logger->debug("Device $device has no fwtables containing anything in vlan $vlan");
            delete $d->{$device}
                if (0 == keys %{$d->{$device}});
        }

        unless (scalar keys %$d && 1 != scalar keys %$d) {
            $logger->debug("No cross-referencing fwtables found in $vlan");
            next;
        }

        # Now we know we actually have data to work with in $d
        # First is the easy case - when we have only A in B's FDB and only B in
        # A's FDB.

        $interfaces = {};

        # Things with a single entry are considered individually
        foreach my $device (keys %$d) {
            foreach my $interface (keys %{$d->{$device}}) {
                $interfaces->{$interface} = $d->{$device}{$interface};
            }
        }

        foreach my $interface (keys %$interfaces) {
            next if (exists $links{$interface});

            my @table = keys %{$interfaces->{$interface}};
            if (1 == scalar @table
                    && 1 == scalar keys %{$interfaces->{$table[0]}}
                    && exists $interfaces->{$table[0]}{$interface} ) {

                $logger->debug("Netdot::Model::Topology::get_fdb_links: Found link: " . $addriface{$interface} . " -> " . $addriface{$table[0]});
                $links{$addriface{$interface}} = $addriface{$table[0]};
                $links{$addriface{$table[0]}} = $addriface{$interface};
            } 
        }

        # Now, if there are any more complicated cases, we do the full
        # algorithm
        sub hash_intersection {
            my ($a, $b) = @_;
            my %combo = ();
            for my $k (keys %$a) { $combo{$k} = 1 if (exists $b->{$k}) }
            return keys %combo;
        }

        sub hash_union {
            my ($a, $b) = @_;
            my %combo = ();
            for my $k (keys %$a) { $combo{$k} = 1 }
            for my $k (keys %$b) { $combo{$k} = 1 }
            return \%combo;
        }

        sub same_hash_keys {
            my ($a, $b) = @_;
            for my $k (keys %$a) { return 0 unless (exists $b->{$k}) }
            for my $k (keys %$b) { return 0 unless (exists $a->{$k}) }
            return 1;
        }

        foreach my $from (keys %$interfaces) {
            next if (exists $links{$from});

            foreach my $to (keys %{$interfaces->{$from}}) {
                if ((0 == scalar hash_intersection($interfaces->{$from}, 
                                                   $interfaces->{$to}))
                        && same_hash_keys(hash_union($interfaces->{$from}, 
                                                      $interfaces->{$to}), 
                                          $interfaces)) {
#                    $logger->debug("Netdot::Model::Topology::get_fdb_links: Found link: " . $addriface{$interface} . " -> " . $addriface{$table[0]});
                    $links{$addriface{$from}} = $addriface{$to};
                    $links{$addriface{$to}} = $addriface{$from};
                    last;
                }
            }
        }
    }

    return \%links;
}

###################################################################################################
=head2 get_stp_links - Get links between devices based on STP information

  Arguments:  
    Hashref with the following keys:
     root  - Address of Root bridge
  Returns:    
    Hashref with link info
  Example:
    my $links = Netdot::Model::Topology->get_stp_links(root=>'DEADDEADBEEF');

=cut
sub get_stp_links {
    my ($self, %argv) = @_;
    $self->isa_class_method('get_stp_links');
    
    # Retrieve all the InterfaceVlan objects that participate in this tree
    my %ivs;
    my @stp_instances = STPInstance->search(root_bridge=>$argv{root});
    map { map { $ivs{$_->id} = $_ } $_->stp_ports } @stp_instances;
    

    # Run the analysis.  The designated bridge on a given segment will 
    # have its own base MAC as the designated bridge and its own STP port ID as 
    # the designated port.  The non-designated bridge will point to the 
    # designated bridge instead.
    my %links;
    $logger->debug(sprintf("Netdot::Model::Topology::get_stp_links: Determining topology for STP tree with root at %s", 
			   $argv{root}));
    my $allmacs = Device->get_macs_from_all();
    my (%far, %near);
    foreach my $ivid ( keys %ivs ){
	my $iv = $ivs{$ivid};
	if ( defined $iv->stp_state && $iv->stp_state =~ /^forwarding|blocking$/ ){
	    if ( $iv->stp_des_bridge && scalar $iv->interface->device ){
		my $des_b     = $iv->stp_des_bridge;
		my $des_p     = $iv->stp_des_port;
		my $int       = $iv->interface->id;
		my $device_id = $iv->interface->device->id;
		# Now, the trick is to determine if the MAC in the designated
		# bridge value belongs to this same switch
		# It can either be the base bridge MAC, or the MAC of one of the
		# interfaces in the switch
		next unless exists $allmacs->{$des_b};
		my $des_device = $allmacs->{$des_b};

		# If the bridge points to itself, it is the designated bridge
		# for the segment, which is nearest to the root
		if ( $des_device && $device_id && $des_device == $device_id ){
		    $near{$des_b}{$des_p} = $int;
		}else{
		    $far{$int}{des_p} = $des_p;
		    $far{$int}{des_b} = $des_b;
		}
	    }
	}
    }
    # Find the port in the designated bridge that is referenced by the far
    # bridge
    foreach my $int ( keys %far ){
	my $des_b = $far{$int}{des_b};
	my $des_p = $far{$int}{des_p};
	if ( exists $near{$des_b} ){
	    if ( exists $near{$des_b}{$des_p} ){
		my $r_int = $near{$des_b}{$des_p};
		$links{$int} = $r_int;
		$logger->debug(sprintf("Netdot::Model::Topology::get_stp_links: Found link: %d -> %d", 
				       $int, $r_int));
	    }else{
		# Octet representations may not match
		foreach my $r_des_p ( keys %{$near{$des_b}} ){
		    if ( $self->_cmp_des_p($r_des_p, $des_p) ){
			my $r_int = $near{$des_b}{$r_des_p};
			$links{$int} = $r_int;
			$logger->debug(sprintf("Netdot::Model::Topology::get_stp_links: Found link: %d -> %d", 
					       $int, $r_int));
		    }
		}
	    }
	}else{
	    $logger->debug(sprintf("Netdot::Model::Topology::get_stp_links: Designated bridge %s not found", 
				   $des_b));
	}
    }
    return \%links;
}


#########################################################################################
#
# Private methods
#
#########################################################################################

############################################################################
# Compare designated Port values
# Depending on the vendor (and the switch model within the same vendor)
# the value of dot1dStpPortDesignatedPort might be represented in different
# ways.  I ignore what the actual logic is, but some times the octets
# are swapped, and one of them may have the most significant or second to most
# significant bit turned on.  Go figure.
sub _cmp_des_p {
    my ($self, $a, $b) = @_;
    my ($aa, $ab, $ba, $bb, $x, $y);
    if ( $a =~ /(\w{2})(\w{2})/ ){
	( $aa, $ab ) = ($1, $2);
    }
    if ( $b =~ /(\w{2})(\w{2})/ ){
	( $ba, $bb ) = ($1, $2);
    }
    if ( $aa eq '00' || $aa eq '80' || $aa eq '40' ){
	$x = $ab;
    }else{
	$x = $aa;
    }
    if ( $ba eq '00' || $ba eq '80' || $ba eq '40' ){
	$y = $bb;
    }else{
	$y = $ba;
    }
    if ( $x eq $y ){
	return 1;
    }
    return 0;
}

=head1 AUTHOR

Carlos Vicente, C<< <cvicente at ns.uoregon.edu> >>

=head1 COPYRIGHT & LICENSE

Copyright 2006 University of Oregon, all rights reserved.

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

