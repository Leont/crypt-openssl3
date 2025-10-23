package Crypt::OpenSSL3::MD;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: message digest algorithms

=head1 SYNOPSIS

 my $md = Crypt::OpenSSL3::MD->fetch('SHA2-256');

 my $context = Crypt::OpenSSL3::MD::Context->new;
 $context->init($md);

 $context->update("Hello, World!");
 my $hash = $context->final;

=head1 DESCRIPTION

This class holds a message digest. It's used to create a L<digest context|Crypt::OpenSSL3::Cipher::Context> that will do the actual digestion.

=method fetch

=method digest

=method get_block_size

=method get_description

=method get_flags

=method get_name

=method get_param

=method get_pkey_type

=method get_size

=method get_type

=method is_a

=method list_all_provided

=method names_list_all

=method xof
