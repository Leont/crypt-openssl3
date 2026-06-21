package Crypt::OpenSSL3::Timestamp::Request;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: A Timestamp Protocol request

=method new

=method add_ext

=method delete_ext

=method get_cert_req

=method get_ext

=method get_exts

=method get_ext_by_NID

=method get_ext_by_OBJ

=method get_ext_by_critical

=method get_ext_count

=method get_msg_imprint

=method get_nonce

=method get_policy_id

=method get_version

=method print

=method read_der

=method set_cert_req

=method set_msg_imprint

=method set_nonce

=method set_policy_id

=method set_version

=method write_der
