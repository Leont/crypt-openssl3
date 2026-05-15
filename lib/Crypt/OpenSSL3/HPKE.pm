package Crypt::OpenSSL3::HPKE;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: Hybrid Public Key Encryption (RFC 9180) suite

=head1 DESCRIPTION

=method new

=method from_string

=method aead_id

=method check

=method default

=method get_ciphertext_size

=method get_grease_value

=method get_public_encap_size

=method get_recommended_ikmelen

=method kdf_id

=method kem_id

=method keygen

=method suite

=head1 CONSTANTS

=head2 KEMs

=over 4

=item *  KEM_ID_P256

=item *  KEM_ID_P384

=item *  KEM_ID_P521

=item *  KEM_ID_X25519

=item *  KEM_ID_X448

=back

=head2 KDFs

=over 4

=item *  KDF_ID_HKDF_SHA256

=item *  KDF_ID_HKDF_SHA384

=item *  KDF_ID_HKDF_SHA512

=back

=head2 AEADs

=over 4

=item *  AEAD_ID_AES_GCM_128

=item *  AEAD_ID_AES_GCM_256

=item *  AEAD_ID_CHACHA_POLY1305

=item *  AEAD_ID_EXPORTONLY

=back

=head2 Modes

=over 4

=item *  MODE_AUTH

=item *  MODE_BASE

=item *  MODE_PSK

=item *  MODE_PSKAUTH

=back

=head2 Roles

=over 4

=item *  ROLE_RECEIVER

=item *  ROLE_SENDER

=back

=head2 Lengths

=over 4

=item *  MAX_INFOLEN

=item *  MAX_PARMLEN

=item *  MIN_PSKLEN

=back
