package Crypt::OpenSSL3::SSL;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An SSL connection

=method new

=method accept

=method accept_connection

=method accept_stream

=method add_client_CA

=method check_private_key

=method clear

=method clear_mode

=method clear_options

=method client_version

=method connect

=method copy_session_id

=method do_handshake

=method get_accept_connection_queue_len

=method get_accept_stream_queue_len

=method get_alpn_selected

=method get_blocking_mode

=method get_certificate

=method get_cipher_list

=method get_connection

=method get_context

=method get_current_cipher

=method get_domain

=method get_domain_flags

=method get_finished

=method get_peer_certificate

=method get_pending_cipher

=method get_error

=method get_event_timeout

=method get_fd

=method get_listener

=method get_mode

=method get_num_tickets

=method get_options

=method get_peer_finished

=method get_privatekey

=method get_read_ahead

=method get_rbio

=method get_rfd

=method get_rpoll_descriptor

=method get_security_level

=method get_session

=method get_servername

=method get_servername_type

=method get_ssl_method

=method get_stream_id

=method get_stream_type

=method get_verify_result

=method get_version

=method get_wbio

=method get_wfd

=method get_wpoll_descriptor

=method handle_events

=method has_pending

=method in_accept_init

=method in_before

=method in_connect_init

=method in_init

=method is_connection

=method is_domain

=method is_dtls

=method is_init_finished

=method is_listener

=method is_server

=method is_stream_local

=method is_tls

=method listen

=method net_read_desired

=method net_write_desired

=method new_domain

=method new_from_listener

=method new_listener

=method new_listener_from

=method new_session_ticket

=method new_stream

=method peek

=method pending

=method read

=method rstate_string

=method rstate_string_long

=method session_reused

=method set_accept_state

=method set_alpn_protos

=method set_blocking_mode

=method set_cipher_list

=method set_ciphersuites

=method set_connect_state

=method set_default_stream_mode

=method set_fd

=method set_host

=method set_incoming_stream_policy

=method set_initial_peer_addr

=method set_max_proto_version

=method set_min_proto_version

=method set_mode

=method set_num_tickets

=method set_options

=method set_post_handshake_auth

=method set_read_ahead

=method set_rbio

=method set_rfd

=method set_security_level

=method set_session

=method set_session_id_context

=method set_tlsext_host_name

=method set_verify

=method set_verify_depth

=method set_wbio

=method set_wfd

=method shutdown

=method state_string

=method state_string_long

=method stream_conclude

=method stream_reset

=method use_PrivateKey

=method use_PrivateKey_ASN1

=method use_PrivateKey_file

=method use_certificate

=method use_certificate_ASN1

=method use_certificate_chain_file

=method use_certificate_file

=method verify_client_post_handshake

=method version

=method write

