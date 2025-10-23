package Crypt::OpenSSL3;

use strict;
use warnings;

use XSLoader;

XSLoader::load(__PACKAGE__, __PACKAGE__->VERSION);

1;

# ABSTRACT: A modern OpenSSL wrapper

=head1 DESCRIPTION

This distribution provides access to the SSL implementation and cryptography provided by OpenSSL. Key packages in this distribution include:

=over 4

=item * L<Crypt::OpenSSL3::SSL|Crypt::OpenSSL3::SSL> - actual SSL connections

=item * L<Crypt::OpenSSL3::PKey|Crypt::OpenSSL3::PKey> - Assymetrical keys

=item * L<Crypt::OpenSSL3::Cipher|Crypt::OpenSSL3::Cipher> - Symmetric ciphers

=item * L<Crypt::OpenSSL3::MD|Crypt::OpenSSL3::MD> - Message digests

=item * L<Crypt::OpenSSL3::MAC|Crypt::OpenSSL3::MAC> - Message Authentication Codes

=item * L<Crypt::OpenSSL3::KDF|Crypt::OpenSSL3::KDF> - Key Derivation Functions

=item * L<Crypt::OpenSSL3::X509|Crypt::OpenSSL3::X509> - X509 certificates

=back

This package itself only two pieces of functionality: error handling and build configuration introspection.

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
