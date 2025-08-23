package Crypt::OpenSSL3;

use strict;
use warnings;

use XSLoader;

XSLoader::load(__PACKAGE__, __PACKAGE__->VERSION);

1;

# ABSTRACT: A modern OpenSSL wrapper


=func clear_error

=func get_error

=func peek_error
