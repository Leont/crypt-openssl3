package Crypt::OpenSSL3::PKey;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An assymetrical key

=head1 SYNOPSIS

 my $file = Crypt::OpenSSL3::BIO->new_file('priv.key', 'r');
 my $key = Crypt::OpenSSL3::Pkey->read_pem_private_key($file);

 my $ctx = Crypt::OpenSSL3::PKey::Context->new($key);
 $ctx->sign_init;
 my $signature = $ctx->sign($data);

=head1 DESCRIPTION

A PKey can be any kind of assymetrical key. This is a fat interface: no single key type supports all possible operations, and most operations aren't supported by all key types. At its core the operations are:

=over 4

=item * encrypt/decrypt

=item * sign/verify

=item * encapsulate/decapsulate

=item * derivation

=item * key generation

=item * parameter generation

=back

=method new

=method new_raw_private_key

=method new_raw_public_key

=method read_pem_private_key

=method read_pem_public_key

=method write_pem_private_key

=method write_pem_public_key

=method can_sign

=method digestsign_supports_digest

=method dup

=method eq

=method get_base_id

=method get_bits

=method get_bn_param

=method get_default_digest_name

=method get_default_digest_nid

=method get_description

=method get_ec_point_conv_form

=method get_encoded_public_key

=method get_field_type

=method get_group_name

=method get_id

=method get_int_param

=method get_octet_string_param

=method get_param

=method get_raw_private_key

=method get_raw_public_key

=method get_security_bits

=method get_size

=method get_size_t_param

=method get_type_name

=method get_utf8_string_param

=method is_a

=method parameters_eq

=method print_params

=method print_private

=method print_public

=method set_bn_param

=method set_encoded_public_key

=method set_int_param

=method set_octet_string_param

=method set_params

=method set_size_t_param

=method set_type

=method set_type_str

=method set_utf8_string_param

=method type

=method type_names_list_all
