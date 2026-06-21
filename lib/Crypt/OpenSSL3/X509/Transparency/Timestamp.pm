package Crypt::OpenSSL3::X509::Transparency::Timestamp;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An X509 certificate

=method new

=method new_from_base64

=method get_extensions

=method get_log_entry_type

=method get_log_id

=method get_signature

=method get_signature_nid

=method get_source

=method get_timestamp

=method get_validation_status

=method get_version

=method set_extensions

=method set_log_entry_type

=method set_log_id

=method set_signature

=method set_signature_nid

=method set_source

=method set_timestamp

=method set_version

=method validate

=head1 CONSTANTS

=over 4

=item ENTRY_TYPE_NOT_SET

=item ENTRY_TYPE_PRECERT

=item ENTRY_TYPE_X509

=item SOURCE_OCSP_STAPLED_RESPONSE

=item SOURCE_TLS_EXTENSION

=item SOURCE_UNKNOWN

=item SOURCE_X509V3_EXTENSION

=item VALIDATION_STATUS_INVALID

=item VALIDATION_STATUS_NOT_SET

=item VALIDATION_STATUS_UNKNOWN_LOG

=item VALIDATION_STATUS_UNKNOWN_VERSION

=item VALIDATION_STATUS_UNVERIFIED

=item VALIDATION_STATUS_VALID

=item VERSION_NOT_SET

=item VERSION_V1

=back
