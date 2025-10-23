package Crypt::OpenSSL3::SSL::Cipher;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An SSL Cipher

=head1 DESCRIPTION

This class holds the algorithm information for a particular cipher which are a core part of the SSL/TLS protocol. The available ciphers are configured on a L<context|Crypt::OpenSSL3::SSL::Context> basis and the actual ones used are then part of the L<session|Crypt::OpenSSL3::SSL::Session>.

=method description

=method get_auth_nid

=method get_bits

=method get_cipher_nid

=method get_digest_nid

=method get_handshake_digest

=method get_id

=method get_kx_nid

=method get_name

=method get_protocol_id

=method get_version

=method is_aead

=method standard_name
