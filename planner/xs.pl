use strict;
use warnings;

use Crypt::OpenSSL::Guess;
use Text::ParseWords 'shellwords';

my @library_paths = map { s/^-L//r } shellwords(openssl_lib_paths());
my @include_paths = map { s/^-I//r } shellwords(openssl_inc_paths());

warn "@library_paths";
warn "@include_paths";

load_module('Dist::Build::XS');

add_xs(
	libraries => ['ssl', 'crypto'],
	library_dirs => \@library_paths,
	include_dirs => \@include_paths,
);
