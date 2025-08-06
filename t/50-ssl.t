#! perl

use strict;
use warnings;

use Test::More;

use Crypt::OpenSSL3::SSL;

my $client_method = Crypt::OpenSSL3::SSL::Method->TLS_client;
my $server_method = Crypt::OpenSSL3::SSL::Method->TLS_server;
my $client_context = Crypt::OpenSSL3::SSL::Context->new($client_method);
my $server_context = Crypt::OpenSSL3::SSL::Context->new($server_method);

$client_context->set_verify(Crypt::OpenSSL3::SSL::VERIFY_NONE);
ok $server_context->use_certificate_chain_file('t/server.crt');
ok $server_context->use_PrivateKey_file('t/server.key', 1);

my $client = Crypt::OpenSSL3::SSL->new($client_context);
ok $client->set_tlsext_host_name('server');
ok $client->set_host('server');

my $server = Crypt::OpenSSL3::SSL->new($server_context);

my ($left, $right) = Crypt::OpenSSL3::BIO->new_bio_pair(4096, 4096);
ok $left;
ok $right;
$client->set_rbio($left);
$client->set_wbio($left);
$server->set_rbio($right);
$server->set_wbio($right);

ok $server->is_server;

my $r1 = $client->connect;
is $r1, -1;
is $client->get_error($r1), Crypt::OpenSSL3::SSL::ERROR_WANT_READ;
is $left->pending, 0;
cmp_ok $right->pending, '>', 0;

my $r2 = $server->accept;
is $r2, -1;
cmp_ok $left->pending, '>', 0;
is $right->pending, 0;
is $server->get_error($r2), Crypt::OpenSSL3::SSL::ERROR_WANT_READ;

is $client->connect, 1;

is $server->accept, 1;

cmp_ok $client->write("Hello, World!"), '>', 0;

is $server->read(my $res1, 15), 13;

is $res1, 'Hello, World!';

done_testing;
