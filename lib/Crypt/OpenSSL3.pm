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

=func info

=over 4

=item INFO_CONFIG_DIR

=item INFO_CPU_SETTINGS

=item INFO_DIR_FILENAME_SEPARATOR

=item INFO_DSO_EXTENSION

=item INFO_ENGINES_DIR

=item INFO_LIST_SEPARATOR

=item INFO_MODULES_DIR

=item INFO_WINDOWS_CONTEXT

=back

=func version

=over 4

=item BUILT_ON

=item CFLAGS

=item CPU_INFO

=item DIR

=item ENGINES_DIR

=item FULL_VERSION_STRING

=item MODULES_DIR

=item PLATFORM

=item VERSION_STRING

=item VERSION_TEXT

=item WINCTX

=back

=func version_build_metadata

=func version_major

=func version_minor

=func version_num

=func version_patch

=func version_pre_release
