package Crypt::OpenSSL3::PKey::Context;

use strict;
use warnings;

1;

# ABSTRACT: An operation using a PKey

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

=method encapsulate

=method encapsulate_init

=method encrypt

=method encrypt_init

=method eq

=method generate

=method get_dh_kdf_md

=method get_dh_kdf_oid

=method get_dh_kdf_outlen

=method get_dh_kdf_type

=method get_ecdh_cofactor_mode

=method get_ecdh_kdf_md

=method get_ecdh_kdf_outlen

=method get_ecdh_kdf_type

=method get_group_name

=method get_id

=method get_keygen_info

=method get_param

=method get_rsa_mgf1_md

=method get_rsa_mgf1_md_name

=method get_rsa_oaep_label

=method get_rsa_oaep_md

=method get_rsa_oaep_md_name

=method get_rsa_padding

=method get_rsa_pss_saltlen

=method get_signature_md

=method is_a

=method keygen_init

=method parameters_eq

=method paramgen_init

=method set_dh_kdf_md

=method set_dh_kdf_oid

=method set_dh_kdf_outlen

=method set_dh_kdf_type

=method set_dh_nid

=method set_dh_pad

=method set_dh_paramgen_generator

=method set_dh_paramgen_gindex

=method set_dh_paramgen_prime_len

=method set_dh_paramgen_seed

=method set_dh_paramgen_subprime_len

=method set_dh_paramgen_type

=method set_dh_rfc5114

=method set_dhx_rfc5114

=method set_dsa_paramgen_bits

=method set_dsa_paramgen_gindex

=method set_dsa_paramgen_md

=method set_dsa_paramgen_md_props

=method set_dsa_paramgen_q_bits

=method set_dsa_paramgen_seed

=method set_dsa_paramgen_type

=method set_ec_param_enc

=method set_ec_paramgen_curve_nid

=method set_ecdh_cofactor_mode

=method set_ecdh_kdf_md

=method set_ecdh_kdf_outlen

=method set_ecdh_kdf_type

=method set_group_name

=method set_hkdf_key

=method set_hkdf_md

=method set_hkdf_mode

=method set_hkdf_salt

=method set_id

=method set_kem_op

=method set_mac_key

=method set_params

=method set_rsa_keygen_bits

=method set_rsa_keygen_primes

=method set_rsa_mgf1_md

=method set_rsa_mgf1_md_name

=method set_rsa_oaep_label

=method set_rsa_oaep_md

=method set_rsa_oaep_md_name

=method set_rsa_padding

=method set_rsa_pss_saltlen

=method set_signature

=method set_signature_md

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
