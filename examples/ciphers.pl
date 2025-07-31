use 5.036;

use Crypt::OpenSSL3;
use Data::Dumper;

say $_->get_name for Crypt::OpenSSL3::Cipher->list_all_provided;

my $key = "0123456789ABCDEF";
my $iv = $key;

my $cipher = Crypt::OpenSSL3::Cipher->fetch("AES-128-CTR");

print Dumper($cipher->get_params);

my $context = Crypt::OpenSSL3::Cipher::Context->new;
$context->init($cipher, $key, $iv, 1, { padding => 0 }) or die;

my $plain = "Hello, World!";

$context->update(my $enc1, $plain) or die;
$context->final(my $enc2) or die;
my $ciphertext = $enc1 . $enc2;
say length $ciphertext;

my $context2 = Crypt::OpenSSL3::Cipher::Context->new;
$context2->init($cipher, $key, $iv, 0) or die;

$context2->update(my $dec1, $ciphertext) or die;
$context2->final(my $dec2) or die;

my $decoded = $dec1 . $dec2;

say $decoded;

print Dumper($context->get_params);
