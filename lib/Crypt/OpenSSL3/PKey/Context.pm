package Crypt::OpenSSL3::PKey::Context;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An operation using a PKey

=head1 SYNOPSIS

 my $ctx = Crypt::OpenSSL3::PKey::Context->new_from_name('RSA');
 $ctx->keygen_init;
 $ctx->set_params({ bits => 2048, primes => 2, e => 65537 });
 my $pkey = $ctx->generate;

=method new

=method new_from_name

=method new_from_pkey

=method new_id

=method add_hkdf_info

=method auth_decapsulate_init

=method auth_encapsulate_init

=method decapsulate

=method decapsulate_init

=method decrypt

=method decrypt_init

=method derive

=method derive_init

=method derive_set_peer

=method dup

=method encapsulate

=method encapsulate_init

=method encrypt

=method encrypt_init

=method generate

=method get_param

=method is_a

=method keygen_init

=method paramgen_init

=method set_params

=method set_signature

=method sign

=method sign_init

=method sign_message_final

=method sign_message_init

=method sign_message_update

=method verify

=method verify_init

=method verify_message_final

=method verify_message_init

=method verify_message_update
