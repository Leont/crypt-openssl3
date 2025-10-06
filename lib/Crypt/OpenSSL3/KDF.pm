package Crypt::OpenSSL3::KDF;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: Key derivation algorithms

=head1 SYNOPSIS

 my $kdf = Crypt::OpenSSL3::KDF->fetch('HKDF');
 my $context = Crypt::OpenSSL3::KDF::Context->new($kdf);
 my $key = 'Hello, World!';
 my $digest = 'SHA2-256';
 my $derived = $context->derive(32, { key => $key, digest => $digest });

=method fetch

=method get_description

=method get_name

=method get_param

=method is_a

=method list_all_provided

=method names_list_all
