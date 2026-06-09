package Crypt::OpenSSL3::Timestamp::Verifier;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: A Timestamp Protocol verifier

=method new

=method add_flags

=method init_from_request

=method set_certs

=method set_data

=method set_flags

=method set_imprint

=method set_store

=method verify_response

=head2 CONSTANTS

=over 4

=item * VFY_DATA

=item * VFY_IMPRINT

=item * VFY_NONCE

=item * VFY_POLICY

=item * VFY_SIGNATURE

=item * VFY_SIGNER

=item * VFY_TSA_NAME

=item * VFY_VERSION

=item * VFY_ALL_DATA

=item * VFY_ALL_IMPRINT

=back
