package Crypt::OpenSSL3::X509::VerifyParam;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: X509 Verification parameters

=method new

=method add_policy

=method add_host

=method clear_flags

=method get_auth_level

=method get_depth

=method get_email

=method get_flags

=method get_host

=method get_hostflags

=method get_inh_flags

=method get_ip_asc

=method get_peername

=method get_purpose

=method get_time

=method set_auth_level

=method set_depth

=method set_email

=method set_flags

=method set_host

=method set_hostflags

=method set_inh_flags

=method set_ip

=method set_ip_asc

=method set_purpose

=method set_time

=method set_trust

=head1 CONSTANTS

=over 4

=item PURPOSE_ANY

=item PURPOSE_CODE_SIGN

=item PURPOSE_CRL_SIGN

=item PURPOSE_NS_SSL_SERVER

=item PURPOSE_OCSP_HELPER

=item PURPOSE_SMIME_ENCRYPT

=item PURPOSE_SMIME_SIGN

=item PURPOSE_SSL_CLIENT

=item PURPOSE_SSL_SERVER

=item PURPOSE_TIMESTAMP_SIGN

=item V_FLAG_ALLOW_PROXY_CERTS

=item V_FLAG_CHECK_SS_SIGNATURE

=item V_FLAG_CRL_CHECK

=item V_FLAG_CRL_CHECK_ALL

=item V_FLAG_EXPLICIT_POLICY

=item V_FLAG_EXTENDED_CRL_SUPPORT

=item V_FLAG_IGNORE_CRITICAL

=item V_FLAG_INHIBIT_ANY

=item V_FLAG_INHIBIT_MAP

=item V_FLAG_NOTIFY_POLICY

=item V_FLAG_NO_ALT_CHAINS

=item V_FLAG_NO_CHECK_TIME

=item V_FLAG_OCSP_RESP_CHECK

=item V_FLAG_OCSP_RESP_CHECK_ALL

=item V_FLAG_PARTIAL_CHAIN

=item V_FLAG_POLICY_CHECK

=item V_FLAG_SUITEB_128_LOS

=item V_FLAG_SUITEB_128_LOS_ONLY

=item V_FLAG_SUITEB_192_LOS

=item V_FLAG_TRUSTED_FIRST

=item V_FLAG_USE_CHECK_TIME

=item V_FLAG_USE_DELTAS

=item V_FLAG_X509_STRICT

=back
