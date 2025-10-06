package Crypt::OpenSSL3::Cipher;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: an abstraction around ciphers

=head1 SYNOPSIS

 my $cipher = Crypt::OpenSSL3::Cipher->fetch('AES-128-GCM');
 my $context = Crypt::OpenSSL3::Cipher::Context->new;
 $context->init($cipher, $key, $iv, 1);
 my $ciphertext = $context->update($plaintext);
 $ciphertext .= $context->final;
 my $tag = $context->get_aead_tag(16);

 my $context2 = Crypt::OpenSSL3::Cipher::Context->new;
 $context2->init($cipher, $key, $iv, 0);
 my $decoded = $context2->update($ciphertext);
 $context2->set_aead_tag($tag);
 $decoded .= $context2->final // die "Invalid tag";

=method fetch

=method get_block_size

=method get_description

=method get_iv_length

=method get_key_length

=method get_mode

=method get_name

=method get_nid

=method get_param

=method get_type

=method is_a

=method list_all_provided

=method names_list_all
