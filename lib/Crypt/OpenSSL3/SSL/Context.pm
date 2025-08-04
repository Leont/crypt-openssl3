package Crypt::OpenSSL3::SSL::Context;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

#ABSTRACT: A context for SSL connections

=method new

=method add_client_CA

=method add_extra_chain_cert

=method add_session

=method clear_extra_chain_certs

=method clear_mode

=method clear_options

=method get_cert_store

=method get_mode

=method get_options

=method load_verify_locations

=method remove_session

=method set_alpn_protos

=method set_cert_store

=method set_cipher_list

=method set_ciphersuites

=method set_default_verify_dir

=method set_default_verify_file

=method set_default_verify_paths

=method set_max_proto_version

=method set_min_proto_version

=method set_mode

=method set_options

=method set_post_handshake_auth

=method set_session_id_context

=method set_verify

=method set_verify_depth

=method use_PrivateKey

=method use_PrivateKey_ASN1

=method use_PrivateKey_file

=method use_certificate

=method use_certificate_ASN1

=method use_certificate_chain_file

=method use_certificate_file

