package Crypt::OpenSSL3::BIO;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An OpenSSL IO instance

=head1 SYNOPSIS

 my $bio = Crypt::OpenSSL3::BIO->new_file('filename', 'r');

 my ($left, $right) = Crypt::OpenSSL3::BIO->new_bio_pair;

=method new_bio_pair

=method new_dgram

=method new_fd

=method new_file

=method new_mem

=method new_socket

=method ctrl_pending

=method ctrl_wpending

=method eof

=method flush

=method get_close

=method get_ktls_recv

=method get_ktls_send

=method get_line

=method get_rpoll_descriptor

=method get_wpoll_descriptor

=method gets

=method pending

=method puts

=method read

=method reset

=method seek

=method set_close

=method tell

=method wpending

=method write
