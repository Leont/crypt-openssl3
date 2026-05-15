package Crypt::OpenSSL3::HPKE::Context;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: Hybrid Public Key Encryption (RFC 9180) context

=head1 SYNOPSIS

 my $sender = $suite->new_sender;
 my $encap = $sender->encapsulate($public, $info);
 my $sealed1 = $sender->seal($payload, $aad);

 my $receiver = $suite->new_receiver;
 $receiver->decapsulate($encap);
 my $unsealed = $receiver->open($sealed1, $aad);


=head1 DESCRIPTION

=method new

=method decapsulate

=method encapsulate

=method export

=method get_seq

=method open

=method seal

=method set_authpriv

=method set_authpub

=method set_ikme

=method set_psk

=method set_seq

=head1 CONSTANTS
