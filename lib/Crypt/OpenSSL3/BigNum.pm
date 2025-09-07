package Crypt::OpenSSL3::BigNum;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: Big Numbers

=method new

=method abs_is_word

=method add

=method add_word

=method are_coprime

=method bin2bn

=method bn2bin

=method bn2binpad

=method bn2dec

=method bn2hex

=method bn2lebinpad

=method bn2mpi

=method bn2nativepad

=method check_prime

=method clear

=method clear_bit

=method cmp

=method copy

=method dec2bn

=method div

=method div_word

=method dup

=method exp

=method gcd

=method generate_prime

=method get_word

=method hex2bn

=method is_bit_set

=method is_odd

=method is_one

=method is_word

=method is_zero

=method lebin2bn

=method lshift

=method lshift1

=method mask_bits

=method mod

=method mod_add

=method mod_exp

=method mod_mul

=method mod_sqr

=method mod_sqrt

=method mod_sub

=method mod_word

=method mpi2bn

=method mul

=method mul_word

=method native2bn

=method nnmod

=method num_bits

=method num_bytes

=method print

=method rand

=method rand_ex

=method rshift

=method rshift1

=method secure_new

=method set_word

=method signed_bin2bn

=method signed_bn2bin

=method signed_bn2lebin

=method signed_bn2native

=method signed_lebin2bn

=method signed_native2bn

=method sqr

=method sub

=method sub_word

=method ucmp

=head1 CONSTANTS

=over 4

=item RAND_BOTTOM_ANY

=item RAND_BOTTOM_ODD

=item RAND_TOP_ANY

=item RAND_TOP_ONE

=item RAND_TOP_TWO

=back
