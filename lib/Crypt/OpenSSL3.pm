package Crypt::OpenSSL3;

use strict;
use warnings;

use XSLoader;

XSLoader::load(__PACKAGE__, __PACKAGE__->VERSION);

1;

# ABSTRACT: A modern OpenSSL wrapper

=method clear_error

=method get_error

=method peek_error

=method error_string
