package Crypt::OpenSSL3::SSL;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An SSL connection

=method new

=method accept

=method add_client_CA

=method clear

=method clear_mode

=method clear_options

=method connect

=method do_handshake

=method get_error

=method get_fd

=method get_mode

=method get_options

=method get_rfd

=method get_servername

=method get_servername_type

=method get_ssl_method

=method get_wfd

=method is_server

=method peek

=method read

=method set_accept_state

=method set_alpn_protos

=method set_cipher_list

=method set_ciphersuites

=method set_connect_state

=method set_fd

=method set_host

=method set_max_proto_version

=method set_min_proto_version

=method set_mode

=method set_options

=method set_post_handshake_auth

=method set_rbio

=method set_rfd

=method set_session_id_context

=method set_tlsext_host_name

=method set_verify

=method set_verify_depth

=method set_wbio

=method set_wfd

=method shutdown

=method use_PrivateKey

=method use_PrivateKey_ASN1

=method use_PrivateKey_file

=method use_certificate

=method use_certificate_ASN1

=method use_certificate_chain_file

=method use_certificate_file

=method verify_client_post_handshake

=method write

