package Crypt::OpenSSL3::SSL::Method;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

#ABSTRACT: Connection funcs for SSL connections

=head1 DESCRIPTION

This is a dispatch structure describing the internal ssl library methods/functions which implement the various protocol versions (SSLv3 TLSv1, ...). It's needed to create a L<context|Crypt::OpenSSL3::SSL::Context>.

=func TLS

=func TLS_client

=func TLS_server

=func DTLS

=func DTLS_client

=func DTLS_server

=func QUIC_client

=func QUIC_client_thread

=func QUIC_server
