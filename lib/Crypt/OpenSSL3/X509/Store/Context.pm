package Crypt::OpenSSL3::X509::Store::Context;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An entry in a X509 store context

=method new

=method get_cert

=method get_chain

=method get_error

=method get_error_string

=method get_error_depth

=method get_num_untrusted

=method get_param

=method get_rpk

=method get_untrusted

=method init

=method init_rpk

=method purpose_inherit

=method set_cert

=method set_default

=method set_error

=method set_error_depth

=method set_param

=method set_purpose

=method set_rpk

=method set_time

=method set_trust

=method set_trusted_stack

=method set_untrusted

=method set_verified_chain

=method verify
