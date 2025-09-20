package Crypt::OpenSSL3::X509;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: An X509 certificate

=method new

=method dup

=method add_ext

=method check_ca

=method check_email

=method check_host

=method check_ip

=method check_ip_asc

=method check_issued

=method check_private_key

=method cmp

=method delete_ext

=method digest

=method digest_sig

=method get_authority_key_id

=method get_authority_serial

=method get_default_cert_dir

=method get_default_cert_dir_env

=method get_default_cert_file

=method get_default_cert_file_env

=method get_distinguishing_id

=method get_ext

=method get_ext_by_NID

=method get_ext_by_OBJ

=method get_ext_by_critical

=method get_ext_count

=method get_extended_key_usage

=method get_extension_flags

=method get_issuer_name

=method get_key_usage

=method get_notAfter

=method get_notBefore

=method get_pathlen

=method get_proxy_pathlen

=method get_pubkey

=method get_serialNumber

=method get_signature

=method get_signature_nid

=method get_subject_key_id

=method get_subject_name

=method get_tbs_sigalg

=method get_version

=method issuer_and_serial_cmp

=method issuer_name_cmp

=method issuer_name_hash

=method pubkey_digest

=method read_pem

=method self_signed

=method set_distinguishing_id

=method set_issuer_name

=method set_notAfter

=method set_notBefore

=method set_proxy_flag

=method set_proxy_pathlen

=method set_pubkey

=method set_serialNumber

=method set_subject_name

=method set_version

=method sign

=method sign_ctx

=method subject_name_cmp

=method subject_name_hash

=method verify

=method write_pem

=head1 CONSTANTS

=over 4

=item CHECK_FLAG_ALWAYS_CHECK_SUBJECT

=item CHECK_FLAG_MULTI_LABEL_WILDCARDS

=item CHECK_FLAG_NEVER_CHECK_SUBJECT

=item CHECK_FLAG_NO_PARTIAL_WILDCARDS

=item CHECK_FLAG_NO_WILDCARDS

=item CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS

=back
