package Crypt::OpenSSL3::SSL::Context;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

#ABSTRACT: A context for SSL connections

=head1 SYNOPSIS

my $method = Crypt::OpenSSL3::SSL::Protocol->TLS_client;
my $ctx = Crypt::OpenSSL3::SSL::Context->new($method);
$ctx->set_verify(Crypt::OpenSSL3::SSL::VERIFY_PEER);
$ctx->set_default_verify_paths();

my $ssl = Crypt::OpenSSL3::SSL->new($ctx);
my $ssl2 = Crypt::OpenSSL3::SSL->new($ctx);
my $ssl3 = Crypt::OpenSSL3::SSL->new($ctx);

=method new

=method add_client_CA

=method add_extra_chain_cert

=method add_session

=method check_private_key

=method clear_extra_chain_certs

=method clear_mode

=method clear_options

=method get_cert_store

=method get_domain_flags

=method get_max_proto_version

=method get_min_proto_version

=method get_mode

=method get_num_tickets

=method get_options

=method get_read_ahead

=method load_verify_dir

=method load_verify_file

=method load_verify_locations

=method load_verify_store

=method remove_session

=method sess_accept

=method sess_accept_good

=method sess_accept_renegotiate

=method sess_cache_full

=method sess_cb_hits

=method sess_connect

=method sess_connect_good

=method sess_connect_renegotiate

=method sess_get_cache_size

=method sess_hits

=method sess_misses

=method sess_number

=method sess_set_cache_size

=method sess_timeouts

=method set_alpn_protos

=method set_cert_store

=method set_cipher_list

=method set_ciphersuites

=method set_default_verify_dir

=method set_default_verify_file

=method set_default_verify_paths

=method set_domain_flags

=method set_max_proto_version

=method set_min_proto_version

=method set_mode

=method set_num_tickets

=method set_options

=method set_post_handshake_auth

=method set_read_ahead

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

