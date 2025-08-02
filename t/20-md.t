#! perl

use strict;
use warnings;

use Test::More;

use Crypt::OpenSSL3;

my @digests = Crypt::OpenSSL3::MD->list_all_provided;
ok @digests, 'Got digests';

my $has_sha256 = grep { $_->get_name eq 'SHA2-256' } @digests;
ok $has_sha256, 'Has SHA-256';

my $md = Crypt::OpenSSL3::MD->fetch('SHA2-256');
ok $md;

my $context = Crypt::OpenSSL3::MD::Context->new;
$context->init($md);

$context->update("Hello, World!");
my $hash = $context->final;
my $expected = pack 'H*', 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f';
is $hash, $expected;

done_testing;
