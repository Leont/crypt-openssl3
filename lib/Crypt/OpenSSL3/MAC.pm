package Crypt::OpenSSL3::MAC;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: Message authentication code algorithms

=head1 SYNOPSIS

 my $algoritm = Crypt::OpenSSL3::MAC->fetch('HMAC');
 my $context = Crypt::OpenSSL3::MAC::Context->new($algoritm);
 my $key = "0123456789ABCDEF";
 $context->init($key, { digest => 'SHA2-256' });

 $context->update('Hello, World!');
 my $mac = $context->final;

=method fetch

=method get_description

=method get_name

=method get_param

=method is_a

=method list_all_provided

=method names_list_all
