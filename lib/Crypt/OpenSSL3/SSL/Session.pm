package Crypt::OpenSSL3::SSL::Session;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: SSL Session state

=head1 DESCRIPTION

This is a class containing the current TLS/SSL session details for a connection: L<cipher|Crypt::OpenSSL3::SSL::Cipher>, client and server certificates, keys, etc.

=method new

=method dup

=method get_alpn_selected

=method get_cipher

=method get_compress_id

=method get_hostname

=method get_id

=method get_id_context

=method get_max_early_data

=method get_peer

=method get_protocol_version

=method get_ticket

=method get_ticket_lifetime_hint

=method get_time

=method get_timeout

=method has_ticket

=method is_resumable

=method print

=method print_keylog

=method set_alpn_selected

=method set_cipher

=method set_hostname

=method set_id

=method set_id_context

=method set_max_early_data

=method set_protocol_version

=method set_time

=method set_timeout
