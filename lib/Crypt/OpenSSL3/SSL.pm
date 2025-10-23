package Crypt::OpenSSL3::SSL;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An SSL connection

=head1 SYNOPSIS

 my $ctx = Crypt::OpenSSL3::SSL::Context->new;
 $ctx->set_default_verify_paths;

 my $ssl = Crypt::OpenSSL3::SSL->new($ctx);
 $ssl->set_verify(Crypt::OpenSSL3::SSL::VERIFY_PEER);
 $ssl->set_fd(fileno $socket);
 $ssl->set_tlsext_host_name($hostname);
 $ssl->set_host($hostname);

 my $ret = $ssl->connect;
 die 'Could not connect: ' . $ssl->get_error($ret) if $ret <= 0;

 my $w_count = $ssl->write("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n");
 die 'Could not write: ' . $ssl->get_error($w_count) if $w_count <= 0;
 my $r_count = $ssl->read(my $buffer, 2048);
 die 'Could not write: ' . $ssl->get_error($r_count) if $r_count <= 0;

=head1 DESCRIPTION

This is the main SSL/TLS class which is created by a server or client per established connection. This actually is the core class in the SSL API. At run-time the application usually deals with this class which has links to mostly all other classes.

Methods in this class generally match functions the C<SSL_*> namespace in C<libssl>.

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

=method is_quic

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

=method sendfile

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

=head1 CONSTANTS

=over 4

=item ERROR_NONE

=item ERROR_SSL

=item ERROR_SYSCALL

=item ERROR_WANT_ACCEPT

=item ERROR_WANT_ASYNC

=item ERROR_WANT_ASYNC_JOB

=item ERROR_WANT_CONNECT

=item ERROR_WANT_READ

=item ERROR_WANT_WRITE

=item ERROR_WANT_X509_LOOKUP

=item ERROR_ZERO_RETURN

=back

=over 4

=item VERIFY_NONE

=item VERIFY_PEER

=item VERIFY_CLIENT_ONCE

=item VERIFY_FAIL_IF_NO_PEER_CERT

=item VERIFY_POST_HANDSHAKE

=back

=over 4

=item TLS1_VERSION

=item TLS1_1_VERSION

=item TLS1_2_VERSION

=item TLS1_3_VERSION

=item DTLS1_VERSION

=item DTLS1_2_VERSION

=item QUIC1_VERSION

=back

=over 4

=item FILETYPE_ASN1

=item FILETYPE_PEM

=back

=over 4

=item MODE_ACCEPT_MOVING_WRITE_BUFFER

=item MODE_ASYNC

=item MODE_AUTO_RETRY

=item MODE_ENABLE_PARTIAL_WRITE

=item MODE_RELEASE_BUFFERS

=item MODE_SEND_FALLBACK_SCSV

=back

=over 4

=item ACCEPT_CONNECTION_NO_BLOCK

=item ACCEPT_STREAM_NO_BLOCK

=item DOMAIN_FLAG_BLOCKING

=item DOMAIN_FLAG_LEGACY_BLOCKING

=item DOMAIN_FLAG_MULTI_THREAD

=item DOMAIN_FLAG_SINGLE_THREAD

=item DOMAIN_FLAG_THREAD_ASSISTED

=item INCOMING_STREAM_POLICY_ACCEPT

=item INCOMING_STREAM_POLICY_AUTO

=item INCOMING_STREAM_POLICY_REJECT

=item STREAM_FLAG_ADVANCE

=item STREAM_FLAG_NO_BLOCK

=item STREAM_FLAG_UNI

=item STREAM_TYPE_BIDI

=item STREAM_TYPE_NONE

=item STREAM_TYPE_READ

=item STREAM_TYPE_WRITE

=back
