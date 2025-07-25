use strict;
use warnings;

load_module('Dist::Build::XS');

add_xs(
	libraries => ['ssl', 'crypto'],
);
