package Crypt::OpenSSL3;

use strict;
use warnings;

use XSLoader;

XSLoader::load(__PACKAGE__, __PACKAGE__->VERSION);

1;

# ABSTRACT: A modern OpenSSL wrapper

=method TLS

=method TLS_client

=method TLS_server

=method DTLS

=method DTLS_client

=method DTLS_server
