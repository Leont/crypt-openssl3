package Crypt::OpenSSL3::Timestamp::TokenInfo;

use strict;
use warnings;

use Crypt::OpenSSL3;

1;

# ABSTRACT: A Timestamp Protocol token information object

=method new

=method add_ext

=method delete_ext

=method get_accuracy

=method get_ext

=method get_ext_by_NID

=method get_ext_by_OBJ

=method get_ext_by_critical

=method get_ext_count

=method get_msg_imprint

=method get_nonce

=method get_ordering

=method get_policy_id

=method get_serial

=method get_time

=method get_tsa

=method get_version

=method print

=method read_der

=method set_accuracy

=method set_msg_imprint

=method set_nonce

=method set_ordering

=method set_policy_id

=method set_serial

=method set_time

=method set_tsa

=method set_version

=method write_der
