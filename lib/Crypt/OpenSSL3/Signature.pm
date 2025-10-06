package Crypt::OpenSSL3::Signature;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: Signature algorithms

=head1 SYNOPSIS

 my $alg = Crypt::OpenSSL3::Signature->fetch('RSA-SHA2-512');
 my $ctx = Crypt::OpenSSL3::PKey::Context->new($pkey);
 $ctx->sign_message_init($alg, { 'pad-mode' => 'pss' });
 while (my $data = $input->get_data) {
   $ctx->sign_message_update($data);
 }
 my $signature = $ctx->sign_message_final;

=method fetch

=method get_description

=method get_name

=method is_a

=method list_all_provided

=method names_list_all
