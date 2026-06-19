package Crypt::OpenSSL3::PKCS7;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: A PKCS7 envelope

=method add_certificate

=method decrypt

=method encrypt

=method get_signers

=method get_octet_string

=method new

=method read_der

=method read_pem

=method sign

=method type_is_data

=method type_is_digest

=method type_is_encrypted

=method type_is_enveloped

=method type_is_other

=method type_is_signed

=method type_is_signedAndEnveloped

=method verify

=method write_der

=method write_pem

=head1 CONSTANTS

=over 4

=item * BINARY

=item * DETACHED

=item * NOATTR

=item * NOCERTS

=item * NOCHAIN

=item * NOCRL

=item * NOINTERN

=item * NOSIGS

=item * NOSMIMECAP

=item * NOVERIFY

=item * STREAM

=item * TEXT

=back
