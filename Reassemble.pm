package Net::Pcap::Reassemble;

use strict;
use vars qw($VERSION %pending $callback $debug);

use Net::Pcap;

#
# Copyright (c) 2006 James Raftery <james@now.ie>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
# Please submit bug reports, patches and comments to the author.
#
# $Id: Reassemble.pm,v 1.2 2006/09/12 11:43:20 james Exp $
#
# This module is a wrapper for the loop() function of the Net::Pcap
# module. It performs IP fragment reassembly for fragmented datagrams
# in the libpcap dump data. You require the Net::Pcap module to use
# Net::Pcap::Reassemble.
# 

$VERSION = '0.01';
$debug   = 0;

####

=head1 NAME

Net::Pcap::Reassemble - IP fragment reassembly for Net::Pcap

=head1 SYNOPSIS

 use Net::Pcap::Reassemble;

 my $pcap_t = Net::Pcap::open_offline($opt_p, \$err);
 if (!defined($pcap_t)) {
   print STDERR "Net::Pcap::open_offline returned error: $err\n";
   exit 1;
 }

 Net::Pcap::Reassemble::loop($pcap_t, -1, \&callback, "user data");

=head1 DESCRIPTION

This module is a wrapper for the loop() function of the Net::Pcap
module. It performs IP fragment reassembly for fragmented datagrams
in the libpcap dump data. It supports reassembly of IPv4 and IPv6
fragments.

=head1 FUNCTIONS

=over 4

=item loop($pcap, $count, \&callback, $user_data)

The C<loop()> function in B<Net::Pcap::Reassemble> is intended as a
seamless wrapper around the same function from B<Net::Pcap> and as such
it takes the same arguments as it. B<Net::Pcap::Reassemble>, however,
will only invoke the C<&callback> function when it has a complete
packet.

The module will print debug information (mainly packet header values) if
the C<$debug> variable in the package namespace evaluates to true:

 $Net::Pcap::Reassemble::debug = 1;

=back

=head1 OBJECTS

Fragment data is represented internally using
C<Net::Pcap::Reassemble::Packet> and C<Net::Pcap::Reassemble::Fragment>
objects.

=over 4

=item Net::Pcap::Reassemble::Packet

Each `Packet' object contains:

=over 2

=item 1

An ID: 'srcip dstip IPid protocol' for IPv4; 'srcip dstip IPid' for IPv6

=item 2

A list of C<Net::Pcap::Reassemble::Fragment> object references

=item 3

The final octet, learned from the packet  with MF==0

=back

=item Net::Pcap::Reassemble::Fragment

Each `Fragment' object contains:

=over 2

=item 1

Start octet

=item 2

End octet

=item 3

(M)ore (F)ragments flag (`MF' in IPv4; `M' in IPv6)

=item 4

Payload data

=back

=back

=head1 SEE ALSO

L<Net::Pcap(3)>

=head1 BUGS

=over 4

=item *

Stale fragments are not aged out of the pending fragment list.

=item *

This module offers no resistance against fragment overlap attacks, and
other such malarky.

=back

=head1 AUTHOR

James Raftery <james@now.ie>.

=cut

####

#
# Wrapper around Net::Pcap's loop() function. This takes the same
# arguments as Net::Pcap's loop().
#
sub loop ($$&$) {

	my ($pcap_t, $num, $user_data);

	($pcap_t, $num, $callback, $user_data) = @_ or 
		croak("Missing arguments to Net::Pcap::Reassemble::loop()");

	#
	# A reference to the user's callback is in $callback, which is
	# declared as a package global. We call Net::Pcap::loop,
	# specifying instead our own _reassemble() sub as its callback.
	# _reassemble() will give a packet to the sub referenced in
	# $callback when it has a complete datagram.
	#
	return Net::Pcap::loop($pcap_t, $num, \&_reassemble, $user_data);
}

#
# Callback function. Read the IP version from the packet header and call
# the appropriate function to read it. If that function returns data
# (i.e. a complete datagram) then summon up the user's callback,
# supplying the packet.
#
sub _reassemble ($$$) {

	my ($user_data, $header, $packet, $ver);

	($user_data, $header, $packet) = @_ or 
		croak("Missing arguments to Net::Pcap::Reassemble::_reassemble()");

	# discard the ethernet header (14 bytes)
	(undef, $ver) = unpack("a14C", $packet);
	$ver = ($ver & 0xf0) >> 4;

	VER: {
		if ($ver == 4)	{
			$packet = _readIPv4pkt($packet);
			last VER;
		}

		if ($ver == 6)	{
			$packet = _readIPv6pkt($packet);
			last VER;
		}

		# default:
			return;

	} # End: VER

	&$callback($user_data, $header, $packet) if $packet;
}

#
# Read an IPv4 packet.
#
sub _readIPv4pkt ($) {

	my ($packet, $i, $ver, $ihl, $len, $id, $mf, $offset, $proto,
	    $src, $dst, $payload, $datalen);

	$packet = shift or
		croak("Missing argument to Net::Pcap::Reassemble::_readIPv4pkt()");

	# XXX what about options ?
	# The undef's are: ethernet header, tos, ttl, chksum, options+data
	(undef, $i, undef, $len, $id, $offset, undef, $proto, undef,
	 $src, $dst, $payload) = unpack("a14CCnnnCCnNNa*", $packet);

	$ver     = ($i & 0xf0) >> 4;
	$ihl     =  $i & 0x0f;
	$mf      = ($offset >> 13) & 0x01;	# More fragments flag
	$offset  = ($offset & 0x1fff) << 3;
	$src     = join(".", unpack("C*", pack("N", $src)));
	$dst     = join(".", unpack("C*", pack("N", $dst)));
	$datalen = $len - $ihl*4;

	print "ver:$ver ihl:$ihl len:$len id:$id mf:$mf " .
		"offset:$offset datalen:$datalen proto:$proto\n".
		"src:$src dst:$dst\n" if $debug;

	#
	# Fragment 1:		MF == 1, offset == 0
	# Fragment 2..(n-1):	MF == 1, offset >  0
	# Fragment n:		MF == 0, offset >  0
	#

	#
	# Can you encounter a negative offset? Maybe if we unpack the
	# data incorrectly.
	#
	# If this isn't a fragment we drop down to the return statement
	# which passes back the unmodified $packet data.
	#
	if (($mf and $offset >= 0) or ($offset > 0)) {
		print "Fragment! ver:$ver ihl:$ihl len:$len id:$id mf:$mf " .
			"offset:$offset datalen:$datalen proto:$proto\n".
			"src:$src dst:$dst\n" if $debug;

		$i = "$src $dst $id $proto";
		
		#
		# Initial fragment - use the whole packet as the data
		# XXX The user callback gets a packet with the header
		#     from the first fragment. 'total length' and MF
		#     are going to be wrong w.r.t. the reassembled
		#     packet.
		#
		$payload = $packet if ($offset == 0);

		#
		# XXX We don't expunge old entries
		#
		if (exists $pending{$i}) {
			$pending{$i}->addfragment($offset, $datalen,
							$mf, $payload) or
				print STDERR "addfragment: $offset $datalen $mf failed\n";
		} else {
			$pending{$i} = Net::Pcap::Reassemble::Packet->new(
					$i, $offset, $datalen, $mf, $payload) or
				print STDERR "new Packet: $i $offset $datalen, $mf failed\n";
		}

		$pending{$i}->listfragments if $debug;

		# We get a packet if all the fragments have arrived, or
		# an empty string if not.
		$packet = $pending{$i}->iscomplete;
		$pending{$i} = undef if $packet;
	}

	return $packet;
}

#
# Read an IPv6 header/packet.
#
sub _readIPv6pkt ($) {

	my ($packet, $ver, $len, $nexthdr, $src, $dst, $payload, $i,
	    $offset, $id, $m, $hdrlen, $totalhdrlen, $unfraggable);

	$packet = shift or
		croak("Missing argument to Net::Pcap::Reassemble::_readIPv6pkt()");

	# The undef's are: ethernet header, class, label, hlim
	(undef, $ver, undef, undef, $len, $nexthdr, undef,
	 $src, $dst, $payload) = unpack("a14CCnnCCH32H32a*", $packet);

	$totalhdrlen = 0;	# counter of header bytes read so far
	$ver         = ($ver & 0xf0) >> 4;
	$src         = join(":", unpack("H4"x8, pack("H32", $src)));
	$dst         = join(":", unpack("H4"x8, pack("H32", $dst)));

	print "ver:$ver len:$len nexthdr:$nexthdr\n" .
			"src:$src\ndst:$dst\n" if $debug;

	#
	# Since this module isn't a v6 capable end-host it doesn't
	# implement TCP or UDP or any other `upper-layer' protocol. How
	# then do we decide when to stop looking ahead to the next
	# header (and return some data to the caller)? We stop when we
	# find a `next header' which isn't known Extension Header:
	#
	# Hop-by-Hop Options header		0
	# Routing header			43
	# Fragment header			44
	# Encapsulating Security Payload header	50
	# Authentication header			51
	# Destination Options header		60
	#
	# This means this will fail to deal with any subsequently added
	# Extension Headers, which is sucky, but the alternative is to
	# list all the other `next headers' values and then break when a
	# new one of them is defined :)
	#
	EXTHEADER: for (;;) {

		#
		# Fragment Header
		#
		if ($nexthdr == 44) {

			($offset, $id, $m, $payload) =
						_readIPv6Fragheader($payload);
			print "Fragment! ver:$ver len:$len nexthdr:$nexthdr " .
				"m:$m offset:$offset id:$id\n" .
				"src:$src\ndst:$dst\n" if $debug;

			$i = "$src $dst $id";

			#
			# Initial fragment - use the whole packet minus
			# the Fragment header as the data.
			# XXX The user callback gets a packet with the header
			#     from the first fragment. `length' is going to be
			#     wrong w.r.t. the reassembled packet.
			#
			if ($offset == 0) {
				$unfraggable = pack("C*",
					unpack("C"x(14+40+$totalhdrlen),
					$packet));
				$payload = $unfraggable . $payload;
			}

			#
			# Fragment length =
			#       packet length - length of headers read
			#	(add 8 bytes for the Fragment header
			#	itself)
			#
			$len -= ($totalhdrlen+8);

			#
			# XXX We don't expunge old entries
			#
			if (exists $pending{$i}) {
				$pending{$i}->addfragment($offset, $len,
							  $m, $payload) or
					print STDERR "addfragment: $offset $len $m failed\n";
			} else {
				$pending{$i} =
					Net::Pcap::Reassemble::Packet->new(
					      $i, $offset, $len, $m, $payload) or
					print STDERR "new Packet: $i $offset $len, $m failed\n";
			}

			$pending{$i}->listfragments if $debug;

			# We get a packet if all the fragments have arrived,
			# or an empty string if not.
			$packet = $pending{$i}->iscomplete;
			$pending{$i} = undef if $packet;
			last EXTHEADER;
		}

		if ($nexthdr ==  0 or $nexthdr == 43 or $nexthdr == 50 or
		    $nexthdr == 51 or $nexthdr == 60) {

			$totalhdrlen += $hdrlen;
			($nexthdr, $hdrlen, $payload) =
						_readIPv6Extheader($payload);
			next EXTHEADER;
		}

		# If the header isn't any of those above, break out of the
		# loop.
		last EXTHEADER;

	} # End: EXTHEADER

	return $packet;
}

#
# Read a standard IPv6 Extension Header. Extract the Next Header and
# Header Length values, and the payload.
#
sub _readIPv6Extheader ($) {

	my ($packet, $nexthdr, $hdrlen, $payload);

	$packet = shift or
		croak("Missing argument to Net::Pcap::Reassemble::_readIPv6Extheader()");

	($nexthdr, $hdrlen) = unpack("CC", $packet);

	$hdrlen = $hdrlen*8 + 8;
	print "Extension header is $hdrlen octets, nexthdr: $nexthdr\n" if $debug;

	# XXX not tested
	$payload = unpack(("x"x $hdrlen)."a*", $packet);

	return($nexthdr, $hdrlen, $payload);
}

#
# Read an IPv6 Fragment Header. Extract the fragment's offset, ID, M
# flag and payload.
#
sub _readIPv6Fragheader ($) {

	my ($packet, $nexthdr, $offset, $m, $id, $payload);

	$packet = shift or
		croak("Missing argument to Net::Pcap::Reassemble::_readIPv6Fragheader()");

	($nexthdr, undef, $offset, $id, $payload) = unpack("CCnNa*", $packet);

	$m        = $offset & 0x0001;
	$offset >>= 3;
	$offset  *= 8;

	print "Fragment extension header: nexthdr:$nexthdr offset:$offset ".
		"id:$id,0x". unpack("H*", pack("N", $id)) ." m:$m\n" if $debug;

	return ($offset, $id, $m, $payload);
}

####

package Net::Pcap::Reassemble::Packet;

use strict;
use Carp;

#
# Constructor for a `Packet' object.
#
sub new {
	my $proto  = shift or croak;
	my $class  = ref($proto) || $proto;
	defined(my $id     = shift) or croak "No ID in Packet constructor";
	defined(my $offset = shift) or croak "No offset in Packet constructor";
	defined(my $length = shift) or croak "No length in Packet constructor";
	defined(my $mf     = shift) or croak "No MF in Packet constructor";
	defined(my $data   = shift) or croak "No data in Packet constructor";

	#
	# Each `Packet' object contains:
	#  1. ID: 'srcip dstip IPid protocol' for IPv4; 'srcip dstip IPid' for IPv6
	#  2. A list of Net::Pcap::Reassemble::Fragment object references
	#  3. The final octet, learned from the packet with MF==0.
	#
	my $self = {
		ID		=> $id,
		FRAGS		=> [],
		LASTOCTET	=> undef,
	};

	bless($self, $class);

	return undef if !$self->addfragment($offset, $length, $mf, $data);

	return $self;
}

#
# Add a fragment to a Packet object.
#
sub addfragment {
	my $self = shift;
	ref($self) or croak;

	my ($offset, $length, $mf, $data) = @_ or croak;

	my $frag =
	  Net::Pcap::Reassemble::Fragment->new($offset, $length, $mf, $data);
	return undef if !$frag;

	# If this is the last fragment, save the last octet value in the
	# object.
	$self->{LASTOCTET} = $offset+$length if !$mf;

	# XXX Test for overlap?
	return push(@{$self->{FRAGS}}, $frag);
}

#
# Print a list of the fragments that have been recieved for the
# Packet object.
#
sub listfragments {
	my $self = shift;
	ref($self) or croak;

	print "Packet ID:'$self->{ID}'\n";
	print "Last octet:$self->{LASTOCTET}\n" if (defined $self->{LASTOCTET});
	foreach (@{$self->{FRAGS}}) {
		print "Fragment start:$_->{START} end:$_->{END} mf:$_->{MF}\n";
	}
}

#
# Check if all the fragments for a Packet have been received. If they have,
# splice the fragment data back together and return to the caller. If they
# have not, returns no data.
#
sub iscomplete {
	my $self = shift;
	ref($self) or croak;

	my $complete = 0;
	my $nextfrag = 0;	# The first fragment starts at octet zero
	my $data     = "";

	#
	# If we don't know LASTOCTET yet then we're missing at least the
	# final (MF==0) fragment so we don't need to proceed any further.
	#
	return if !defined $self->{LASTOCTET};

	#
	# Sort the fragment list so we only need to scan it once.
	# If it was unordered we would need to scan through it repeatedly.
	# That said, sort() is pretty slow :)
	#
	@{$self->{FRAGS}} = sort {$a->{START}<=>$b->{START}} @{$self->{FRAGS}};

	FRAGMENT: foreach (@{$self->{FRAGS}}) {

		#
		# If the first octet in this fragment is the octet we're
		# searching for ...
		#
		if ($_->{START} == $nextfrag) {

			#
			# ... and the last octet is the last octet of the
			# complete datagram, then we have all the packet
			# data ...
			#
			if ($_->{END} == $self->{LASTOCTET}) {
				$complete = 1;
				last FRAGMENT;	# We're done!
			}

			#
			# ... but if the last octet is not the last octet of
			# the complete datagram, then the next fragment we
			# search for is the one that starts where this one
			# ends.
			#
			$nextfrag = $_->{END};
			next FRAGMENT;
		}

		#
		# If we reach here, we're missing at least one fragment so 
		# just give up.
		#
		last FRAGMENT;
	}

	#
	# If the datagram is complete, splice the fragments' data together
	# to return the complete packet.
	#
	if ($complete) {
		foreach (@{$self->{FRAGS}}) {
			$data .= $_->{DATA};
		}
		return $data;
	}

	#
	# Otherwise return nothing.
	#
	return;
}

####

package Net::Pcap::Reassemble::Fragment;

use strict;
use Carp;

#
# Constructor for a `Fragment' object.
#
sub new {
	my $proto  = shift or croak();
	my $class  = ref($proto) || $proto;
	defined(my $offset = shift) or croak "No offset in Fragment constructor";
	defined(my $length = shift) or croak "No length in Fragment constructor";
	defined(my $mf     = shift) or croak "No MF in Fragment constructor";
	defined(my $data   = shift) or croak "No data in Fragment constructor";

	#
	# Each `Fragment' object contains:
	#  1. Start octet
	#  2. End octet
	#  3. (M)ore (F)ragments flag (`MF' in IPv4; `M' in IPv6)
	#  4. Payload data
	#
	my $self = {
		START	=> $offset,
		END	=> $offset+$length,
		MF	=> $mf,
		DATA	=> $data,
	};

	bless($self, $class);
	return $self;
}

####

1;

__END__
