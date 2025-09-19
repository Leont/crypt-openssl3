package Crypt::OpenSSL3::PKey;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An assymetrical key

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
