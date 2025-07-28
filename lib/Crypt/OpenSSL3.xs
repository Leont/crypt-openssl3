#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/ssl.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>

#define DUPLICATING_TYPE(c_prefix, xs_type)\
typedef c_prefix * Crypt__OpenSSL3__ ## xs_type;\
static int c_prefix ## _magic_dup(pTHX_ MAGIC* mg, CLONE_PARAMS* params) {\
	mg->mg_ptr = (char*)c_prefix ## _dup((c_prefix*)mg->mg_ptr);\
	return 0;\
}\
static int c_prefix ## _magic_free(pTHX_ SV* sv, MAGIC* mg) {\
	c_prefix ## _free((c_prefix*)mg->mg_ptr);\
	return 0;\
}\
static const MGVTBL Crypt__OpenSSL3__ ## xs_type ## _magic = {\
	.svt_dup = c_prefix ## _magic_dup,\
	.svt_free = c_prefix ## _magic_free,\
};

#define COUNTING_TYPE(c_prefix, xs_type)\
typedef c_prefix * Crypt__OpenSSL3__ ## xs_type;\
static int c_prefix ## _magic_dup(pTHX_ MAGIC* mg, CLONE_PARAMS* params) {\
	c_prefix ## _up_ref((c_prefix*)mg->mg_ptr);\
	return 0;\
}\
static int c_prefix ## _magic_free(pTHX_ SV* sv, MAGIC* mg) {\
	c_prefix ## _free((c_prefix*)mg->mg_ptr);\
	return 0;\
}\
static const MGVTBL Crypt__OpenSSL3__ ## xs_type ## _magic = {\
	.svt_dup = c_prefix ## _magic_dup,\
	.svt_free = c_prefix ## _magic_free,\
};

#define SIMPLE_TYPE(c_prefix, xs_type, modifier)\
typedef modifier c_prefix * Crypt__OpenSSL3__ ## xs_type;\
static const MGVTBL Crypt__OpenSSL3__ ## xs_type ## _magic = { NULL };

COUNTING_TYPE(EVP_CIPHER, Cipher)
DUPLICATING_TYPE(EVP_CIPHER_CTX, Cipher__Context)
COUNTING_TYPE(EVP_MD, MD)
DUPLICATING_TYPE(EVP_MD_CTX, MD__Context)
COUNTING_TYPE(EVP_MAC, MAC)
DUPLICATING_TYPE(EVP_MAC_CTX, MAC__Context)
COUNTING_TYPE(EVP_KDF, KDF)
DUPLICATING_TYPE(EVP_KDF_CTX, KDF__Context)
COUNTING_TYPE(EVP_PKEY, PrivateKey)

typedef BIGNUM BN;
DUPLICATING_TYPE(BN, BigNum);
#define BN_CTX_dup(old) BN_CTX_new()
DUPLICATING_TYPE(BN_CTX, BigNum__Context)
COUNTING_TYPE(X509, X509)
COUNTING_TYPE(X509_STORE, X509__Store)
DUPLICATING_TYPE(X509_NAME, X509__Name)
DUPLICATING_TYPE(X509_NAME_ENTRY, X509__Name__Entry)
typedef long Crypt__OpenSSL3__X509__VerifyResult;

COUNTING_TYPE(BIO, BIO)

SIMPLE_TYPE(SSL_METHOD, SSL__Protocol, const)
COUNTING_TYPE(SSL_CTX, SSL__Context)
COUNTING_TYPE(SSL, SSL)
COUNTING_TYPE(SSL_SESSION, SSL__Session)

typedef long SysRet;

SV* S_make_object(pTHX_ void* var, const MGVTBL* mgvtbl, const char* ntype) {
	SV* result = newSV(0);
	MAGIC* magic = sv_magicext(newSVrv(result, ntype), NULL, PERL_MAGIC_ext, mgvtbl, (const char*)var, 0);
	magic->mg_flags |= MGf_DUP;
	return result;
}
#define make_object(var, magic, name) S_make_object(aTHX_ var, magic, name)

#define BIO_new_mem(class) BIO_new(BIO_s_mem())
#define BN_generate_prime BN_generate_prime_ex2
#define X509_verify_cert_error_code(value) value
#define X509_verify_cert_ok(value) (value == X509_V_OK)

#define TLS(class) TLS_method()
#define TLS_server(class) TLS_server_method()
#define TLS_client(class) TLS_client_method()

#define DTLS(class) DTLS_method()
#define DTLS_server(class) DTLS_server_method()
#define DTLS_client(class) DTLS_client_method()

#define SSL_Method_context SSL_CTX_new

#define SSL_set_host SSL_set1_host
#define SSL_set_rbio SSL_set0_rbio
#define SSL_set_wbio SSL_set0_wbio

#define SSL_SESSION_get_peer SSL_SESSION_get0_peer

#define EVP_CIPHER_get_name EVP_CIPHER_get0_name
#define EVP_CIPHER_get_description EVP_CIPHER_get0_description
#define EVP_CIPHER_CTX_get_name EVP_CIPHER_CTX_get0_name
#define EVP_CIPHER_CTX_get_cipher EVP_CIPHER_CTX_get1_cipher

#define EVP_MD_get_name EVP_MD_get0_name
#define EVP_MD_get_description EVP_MD_get0_description
#undef EVP_MD_CTX_init
#define EVP_MD_CTX_get_md EVP_MD_CTX_get1_md
#define EVP_MD_CTX_get_name EVP_MD_CTX_get0_name
#define EVP_MD_CTX_init EVP_DigestInit_ex2
#define EVP_MD_CTX_update EVP_DigestUpdate
#define EVP_MD_CTX_final EVP_DigestFinal_ex
#define EVP_MD_CTX_final_xof EVP_DigestFinalXOF
#define EVP_MD_CTX_squeeze EVP_DigestSqueeze

#define EVP_MAC_get_name EVP_MAC_get0_name
#define EVP_MAC_get_description EVP_MAC_get0_description
#define EVP_MAC_CTX_get_mac EVP_MAC_CTX_get0_mac
#define EVP_MAC_CTX_get_name EVP_MAC_CTX_get0_name

#define EVP_KDF_get_name EVP_KDF_get0_name
#define EVP_KDF_get_description EVP_KDF_get0_description
#define EVP_KDF_CTX_get_name EVP_KDF_CTX_get0_name

#define CONSTANT2(PREFIX, VALUE) newCONSTSUB(stash, #VALUE, newSVuv(PREFIX##VALUE))

char* S_grow_buffer(pTHX_ SV* buffer, size_t size) {
	SvUPGRADE(buffer, SVt_PV);
	SV_CHECK_THINKFIRST(buffer);
	SvPOK_only(buffer);
	return SvGROW(buffer, size);
}
#define grow_buffer(sv, size) S_grow_buffer(aTHX_ sv, size)

#define set_buffer_length(buffer, result) STMT_START { if (result >= 0) SvCUR_set(buffer, result); } STMT_END

static const OSSL_PARAM* S_params_for(pTHX_ const OSSL_PARAM* settable, SV* sv) {
	static const OSSL_PARAM empty_PARAMS = OSSL_PARAM_DEFN(NULL, 0, NULL, 0);
	if (!SvROK(sv) || SvTYPE(SvRV(sv)) != SVt_PVHV)
		return &empty_PARAMS;

	OSSL_PARAM_BLD* builder = OSSL_PARAM_BLD_new();
	HV* hash = (HV*)SvRV(sv);
	while (settable->key) {
		SV** sv_ptr = hv_fetch(hash, settable->key, strlen(settable->key), 0);
		if (sv_ptr && *sv_ptr) {
			if (settable->data_type == OSSL_PARAM_INTEGER)
				OSSL_PARAM_BLD_push_int64(builder, settable->key, SvIV(*sv_ptr));
			else if (settable->data_type == OSSL_PARAM_UNSIGNED_INTEGER)
				OSSL_PARAM_BLD_push_uint64(builder, settable->key, SvUV(*sv_ptr));
			else if (settable->data_type == OSSL_PARAM_REAL)
				OSSL_PARAM_BLD_push_double(builder, settable->key, SvNV(*sv_ptr));
			else if (settable->data_type == OSSL_PARAM_UTF8_STRING) {
				STRLEN length;
				const char* ptr = SvPVutf8(*sv_ptr, length);
				OSSL_PARAM_BLD_push_utf8_string(builder, settable->key, ptr, length);
			} else if (settable->data_type == OSSL_PARAM_OCTET_STRING) {
				STRLEN length;
				const char* ptr = SvPVbyte(*sv_ptr, length);
				OSSL_PARAM_BLD_push_octet_string(builder, settable->key, ptr, length);
			}
		}
		settable++;
	}

	OSSL_PARAM* result = OSSL_PARAM_BLD_to_param(builder);
	OSSL_PARAM_BLD_free(builder);
	SAVEDESTRUCTOR(OSSL_PARAM_free, result);
	return result;
}
#define params_for(settable, sv) S_params_for(aTHX_ settable, sv)

struct EVP_callback_data {
#ifdef MULTIPLICITY
	PerlInterpreter* interpreter;
#endif
	SV* sv;
};

void S_call_callback(pTHX_ SV* callback, SV* value) {
	dSP;
	PUSHMARK(SP);
	mXPUSHs(value);
	PUTBACK;
	call_sv(callback, G_VOID | G_DISCARD);
}
#define call_callback(value, callback) S_call_callback(aTHX_ value, callback)

void EVP_name_callback(const char* name, void* vdata) {
	struct EVP_callback_data* data = vdata;
	dTHXa(data->interpreter);
	call_callback(data->sv, newSVpv(name, 0));
}

#define DEFINE_PROVIDED_CALLBACK(c_type, name)\
static void c_type ## _provided_callback(c_type* provided, void* vdata) {\
	struct EVP_callback_data* data = vdata;\
	dTHXa(data->interpreter);\
	c_type ## _up_ref(provided);\
	SV* object = make_object(provided, &Crypt__OpenSSL3__ ## name ## _magic, "Crypt::OpenSSL3::" #name);\
	call_callback(data->sv, object);\
}
DEFINE_PROVIDED_CALLBACK(EVP_CIPHER, Cipher)
DEFINE_PROVIDED_CALLBACK(EVP_MD, MD)
DEFINE_PROVIDED_CALLBACK(EVP_MAC, MAC)
DEFINE_PROVIDED_CALLBACK(EVP_KDF, KDF)

#define undef &PL_sv_undef

// This will force byte semantics on all strings
// This should come as the last thing in the C section of this file
#undef SvPV
#define SvPV(sv, len) SvPVbyte(sv, len)
#undef SvPV_nolen
#define SvPV_nolen(sv) SvPVbyte_nolen(sv)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3

TYPEMAP: <<END
const unsigned char*	T_PV

Crypt::OpenSSL3::Cipher T_MAGICEXT
Crypt::OpenSSL3::Cipher::Context T_MAGICEXT
Crypt::OpenSSL3::MD T_MAGICEXT
Crypt::OpenSSL3::MD::Context T_MAGICEXT
Crypt::OpenSSL3::MAC T_MAGICEXT
Crypt::OpenSSL3::MAC::Context T_MAGICEXT
Crypt::OpenSSL3::KDF T_MAGICEXT
Crypt::OpenSSL3::KDF::Context T_MAGICEXT
Crypt::OpenSSL3::PrivateKey T_MAGICEXT

Crypt::OpenSSL3::BIO T_MAGICEXT

Crypt::OpenSSL3::BigNum T_MAGICEXT
Crypt::OpenSSL3::BigNum::Context T_MAGICEXT

Crypt::OpenSSL3::X509	T_MAGICEXT
Crypt::OpenSSL3::X509::Store	T_MAGICEXT
Crypt::OpenSSL3::X509::Name	T_MAGICEXT
Crypt::OpenSSL3::X509::Name::Entry	T_MAGICEXT
Crypt::OpenSSL3::X509::VerifyResult T_INTOBJ

Crypt::OpenSSL3::SSL::Protocol T_MAGICEXT
Crypt::OpenSSL3::SSL::Context T_MAGICEXT
Crypt::OpenSSL3::SSL T_MAGICEXT
Crypt::OpenSSL3::SSL::Session T_MAGICEXT
END

Crypt::OpenSSL3::SSL::Protocol TLS(SV* class)

Crypt::OpenSSL3::SSL::Protocol TLS_server(SV* class)

Crypt::OpenSSL3::SSL::Protocol TLS_client(SV* class)

Crypt::OpenSSL3::SSL::Protocol DTLS(SV* class)

Crypt::OpenSSL3::SSL::Protocol DTLS_server(SV* class)

Crypt::OpenSSL3::SSL::Protocol DTLS_client(SV* class)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::BIO	PREFIX = BIO_

Crypt::OpenSSL3::BIO BIO_new_file(SV* class, const char *filename, const char *mode)
C_ARGS:
	filename, mode

Crypt::OpenSSL3::BIO BIO_new_mem(SV* class);

bool BIO_reset(Crypt::OpenSSL3::BIO b)

int BIO_seek(Crypt::OpenSSL3::BIO b, int ofs)

int BIO_tell(Crypt::OpenSSL3::BIO b)

bool BIO_flush(Crypt::OpenSSL3::BIO b)

bool BIO_eof(Crypt::OpenSSL3::BIO b)

bool BIO_set_close(Crypt::OpenSSL3::BIO b, long flag)

int BIO_get_close(Crypt::OpenSSL3::BIO b)

int BIO_pending(Crypt::OpenSSL3::BIO b)

int BIO_wpending(Crypt::OpenSSL3::BIO b)

size_t BIO_ctrl_pending(Crypt::OpenSSL3::BIO b)

size_t BIO_ctrl_wpending(Crypt::OpenSSL3::BIO b)

int BIO_read(Crypt::OpenSSL3::BIO b, SV* buffer, int size)
INIT:
	char* ptr = grow_buffer(buffer, size);
C_ARGS:
	b, ptr, size
POSTCALL:
	set_buffer_length(buffer, RETVAL);

int BIO_gets(Crypt::OpenSSL3::BIO b, SV* buffer, int size)
INIT:
	char* ptr = grow_buffer(buffer, size);
C_ARGS:
	b, ptr, size
POSTCALL:
	set_buffer_length(buffer, RETVAL);

int BIO_get_line(Crypt::OpenSSL3::BIO b, SV* buffer, int size)
INIT:
	char* ptr = grow_buffer(buffer, size);
C_ARGS:
	b, ptr, size
POSTCALL:
	set_buffer_length(buffer, RETVAL);

int BIO_write(Crypt::OpenSSL3::BIO b, const char *data, int length(data))



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::BigNum	PREFIX = BN_

BOOT:
{
	HV* stash = get_hv("Crypt::OpenSSL3::BigNum", TRUE);
	CONSTANT2(BN_, RAND_TOP_ANY);
	CONSTANT2(BN_, RAND_TOP_ONE);
	CONSTANT2(BN_, RAND_TOP_TWO);

	CONSTANT2(BN_, RAND_BOTTOM_ANY);
	CONSTANT2(BN_, RAND_BOTTOM_ODD);
}


Crypt::OpenSSL3::BigNum BN_new(SV* class)
C_ARGS:

Crypt::OpenSSL3::BigNum BN_secure_new(SV* class)
C_ARGS:

void BN_clear(Crypt::OpenSSL3::BigNum a)

bool BN_add(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b)

bool BN_sub(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b)

bool BN_mul(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_sqr(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_div(Crypt::OpenSSL3::BigNum dv, Crypt::OpenSSL3::BigNum rem, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum d, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_mod(Crypt::OpenSSL3::BigNum rem, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum m, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_nnmod(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum m, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_mod_add(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b, Crypt::OpenSSL3::BigNum m, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_mod_sub(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b, Crypt::OpenSSL3::BigNum m, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_mod_mul(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b, Crypt::OpenSSL3::BigNum m, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_mod_sqr(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum m, Crypt::OpenSSL3::BigNum::Context ctx)

Crypt::OpenSSL3::BigNum BN_mod_sqrt(Crypt::OpenSSL3::BigNum in, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum p, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_exp(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum p, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_mod_exp(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum p, Crypt::OpenSSL3::BigNum m, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_gcd(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b, Crypt::OpenSSL3::BigNum::Context ctx)

int BN_num_bytes(Crypt::OpenSSL3::BigNum a)

int BN_num_bits(Crypt::OpenSSL3::BigNum a)

int BN_bn2bin(Crypt::OpenSSL3::BigNum a, SV* buffer)
INIT:
	char* ptr = grow_buffer(buffer, BN_num_bytes(a));
C_ARGS:
	a, ptr
POSTCALL:
	set_buffer_length(buffer, RETVAL);

SysRet BN_bn2binpad(Crypt::OpenSSL3::BigNum a, SV* buffer, int tolen)
INIT:
	char* ptr = grow_buffer(buffer, tolen);
C_ARGS:
	a, ptr, tolen
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(buffer, RETVAL);

Crypt::OpenSSL3::BigNum BN_bin2bn(const unsigned char *s, int len)
C_ARGS: s, len, NULL


SysRet BN_bn2lebinpad(Crypt::OpenSSL3::BigNum a, SV* buffer, int tolen)
INIT:
	char* ptr = grow_buffer(buffer, tolen);
C_ARGS:
	a, ptr, tolen
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(buffer, RETVAL);

Crypt::OpenSSL3::BigNum BN_lebin2bn(const unsigned char *s, int len, Crypt::OpenSSL3::BigNum ret)
C_ARGS: s, len, NULL


SysRet BN_bn2nativepad(Crypt::OpenSSL3::BigNum a, SV* buffer, int tolen)
INIT:
	char* ptr = grow_buffer(buffer, tolen);
C_ARGS:
	a, ptr, tolen
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(buffer, RETVAL);

Crypt::OpenSSL3::BigNum BN_native2bn(const unsigned char *s, int len, Crypt::OpenSSL3::BigNum ret)
C_ARGS: s, len, NULL


char *BN_bn2hex(Crypt::OpenSSL3::BigNum a)
CLEANUP:
	OPENSSL_free(RETVAL);

char *BN_bn2dec(Crypt::OpenSSL3::BigNum a)
CLEANUP:
	OPENSSL_free(RETVAL);

int BN_hex2bn(Crypt::OpenSSL3::BigNum a, const char *str)
C_ARGS:
	&a, str

int BN_dec2bn(Crypt::OpenSSL3::BigNum a, const char *str)
C_ARGS:
	&a, str

bool BN_print(Crypt::OpenSSL3::BIO fp, Crypt::OpenSSL3::BigNum a)


int BN_bn2mpi(Crypt::OpenSSL3::BigNum a, SV* buffer)
INIT:
	char* ptr = grow_buffer(buffer, BN_bn2mpi(a, NULL));
C_ARGS:
	a, ptr
POSTCALL:
	set_buffer_length(buffer, RETVAL);

Crypt::OpenSSL3::BigNum BN_mpi2bn(unsigned char *s, int len)
C_ARGS:
	s, len, NULL

bool BN_check_prime(Crypt::OpenSSL3::BigNum p, Crypt::OpenSSL3::BigNum::Context ctx)
C_ARGS:
	p, ctx, NULL

bool BN_generate_prime(Crypt::OpenSSL3::BigNum ret, int bits, int safe, Crypt::OpenSSL3::BigNum add, Crypt::OpenSSL3::BigNum rem, Crypt::OpenSSL3::BigNum::Context ctx)
C_ARGS:
	ret, bits, safe, add, rem, NULL, ctx

bool BN_set_word(Crypt::OpenSSL3::BigNum a, UV w)

UV BN_get_word(Crypt::OpenSSL3::BigNum a)

bool BN_add_word(Crypt::OpenSSL3::BigNum a, UV w)

bool BN_sub_word(Crypt::OpenSSL3::BigNum a, UV w)

bool BN_mul_word(Crypt::OpenSSL3::BigNum a, UV w)

UV BN_div_word(Crypt::OpenSSL3::BigNum a, UV w)

UV BN_mod_word(Crypt::OpenSSL3::BigNum a, UV w)

int BN_cmp(Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b)

int BN_ucmp(Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b)

bool BN_is_zero(Crypt::OpenSSL3::BigNum a)

bool BN_is_one(Crypt::OpenSSL3::BigNum a)

bool BN_is_word(Crypt::OpenSSL3::BigNum a, UV w)

bool BN_abs_is_word(Crypt::OpenSSL3::BigNum a, UV w)

bool BN_is_odd(Crypt::OpenSSL3::BigNum a)

bool BN_are_coprime(Crypt::OpenSSL3::BigNum a, Crypt::OpenSSL3::BigNum b, Crypt::OpenSSL3::BigNum::Context ctx);


bool BN_clear_bit(Crypt::OpenSSL3::BigNum a, int n)

bool BN_is_bit_set(Crypt::OpenSSL3::BigNum a, int n)

bool BN_mask_bits(Crypt::OpenSSL3::BigNum a, int n)

bool BN_lshift(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, int n)

bool BN_lshift1(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a)

bool BN_rshift(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a, int n)

bool BN_rshift1(Crypt::OpenSSL3::BigNum r, Crypt::OpenSSL3::BigNum a)

bool BN_rand_ex(Crypt::OpenSSL3::BigNum rnd, int bits, int top, int bottom, unsigned int strength, Crypt::OpenSSL3::BigNum::Context ctx)

bool BN_rand(Crypt::OpenSSL3::BigNum rnd, int bits, int top, int bottom)


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::BigNum::Context	PREFIX = BN_CTX_

Crypt::OpenSSL3::BigNum::Context BN_CTX_new(SV* class)
C_ARGS:

Crypt::OpenSSL3::BigNum::Context BN_CTX_secure_new()
C_ARGS:

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::X509	PREFIX = X509_

Crypt::OpenSSL3::X509::Name X509_get_subject_name(Crypt::OpenSSL3::X509 x)

bool X509_set_subject_name(Crypt::OpenSSL3::X509 x, Crypt::OpenSSL3::X509::Name name)

Crypt::OpenSSL3::X509::Name X509_get_issuer_name(Crypt::OpenSSL3::X509 x)

bool X509_set_issuer_name(Crypt::OpenSSL3::X509 x, Crypt::OpenSSL3::X509::Name name)

bool X509_digest(Crypt::OpenSSL3::X509 data, Crypt::OpenSSL3::MD type, SV* buffer)
INIT:
	unsigned int output_length = EVP_MD_size(type);
	char* ptr = grow_buffer(buffer, output_length);
C_ARGS:
	data, type, ptr, &output_length
POSTCALL:
	set_buffer_length(buffer, output_length);

bool X509_pubkey_digest(Crypt::OpenSSL3::X509 data, Crypt::OpenSSL3::MD type, SV* buffer)
INIT:
	unsigned int output_length = EVP_MD_size(type);
	char* ptr = grow_buffer(buffer, output_length);
C_ARGS:
	data, type, ptr, &output_length
POSTCALL:
	set_buffer_length(buffer, output_length);


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::X509::VerifyResult	PREFIX = X509_verify_cert_

IV X509_verify_cert_error_code(Crypt::OpenSSL3::X509::VerifyResult result)

bool X509_verify_cert_ok(Crypt::OpenSSL3::X509::VerifyResult result)

const char* X509_verify_cert_error_string(Crypt::OpenSSL3::X509::VerifyResult result)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::X509::Name	PREFIX = X509_NAME_

int X509_NAME_cmp(Crypt::OpenSSL3::X509::Name a, Crypt::OpenSSL3::X509::Name b)

int X509_NAME_get_index_by_NID(Crypt::OpenSSL3::X509::Name name, int nid, int lastpos)

int X509_NAME_entry_count(Crypt::OpenSSL3::X509::Name name)

Crypt::OpenSSL3::X509::Name::Entry X509_NAME_get_entry(Crypt::OpenSSL3::X509::Name name, int loc)

char* X509_NAME_oneline(Crypt::OpenSSL3::X509::Name a)
	C_ARGS:
		a, NULL, 0
	CLEANUP:
		if (RETVAL)
			OPENSSL_free(RETVAL);

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::X509::Name::Entry	PREFIX = X509_NAME_ENTRY



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::X509::Store	PREFIX = X509_STORE_

bool X509_STORE_add_cert(Crypt::OpenSSL3::X509::Store ctx, Crypt::OpenSSL3::X509 x)

bool X509_STORE_set_depth(Crypt::OpenSSL3::X509::Store store, int depth)

bool X509_STORE_set_flags(Crypt::OpenSSL3::X509::Store ctx, unsigned long flags)

bool X509_STORE_set_purpose(Crypt::OpenSSL3::X509::Store ctx, int purpose)

bool X509_STORE_set_trust(Crypt::OpenSSL3::X509::Store ctx, int trust)

bool X509_STORE_load_locations(Crypt::OpenSSL3::X509::Store ctx, const char *file, const char *dir)

bool X509_STORE_set_default_paths(Crypt::OpenSSL3::X509::Store ctx)


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::SSL::Protocol	PREFIX = SSL_Method_

Crypt::OpenSSL3::SSL::Context SSL_Method_context(Crypt::OpenSSL3::SSL::Protocol method)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::SSL::Context	PREFIX = SSL_CTX_

long SSL_CTX_set_options(Crypt::OpenSSL3::SSL::Context ctx, long options)

long SSL_CTX_clear_options(Crypt::OpenSSL3::SSL::Context ctx, long options)

long SSL_CTX_get_options(Crypt::OpenSSL3::SSL::Context ctx)

bool SSL_CTX_set_session_id_context(Crypt::OpenSSL3::SSL::Context ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len)

long SSL_CTX_set_mode(Crypt::OpenSSL3::SSL::Context ctx, long mode)

long SSL_CTX_clear_mode(Crypt::OpenSSL3::SSL::Context ctx, long mode)

long SSL_CTX_get_mode(Crypt::OpenSSL3::SSL::Context ctx)

bool SSL_CTX_set_min_proto_version(Crypt::OpenSSL3::SSL::Context ctx, int version)

bool SSL_CTX_set_max_proto_version(Crypt::OpenSSL3::SSL::Context ctx, int version)

bool SSL_CTX_set_alpn_protos(Crypt::OpenSSL3::SSL::Context ctx, const unsigned char *protos, unsigned int protos_len)

Crypt::OpenSSL3::X509::Store SSL_CTX_get_cert_store(Crypt::OpenSSL3::SSL::Context ctx)
POSTCALL:
	X509_STORE_up_ref(RETVAL);

void SSL_CTX_set_cert_store(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::X509::Store store)
POSTCALL:
	X509_STORE_up_ref(store);

bool SSL_CTX_load_verify_locations(Crypt::OpenSSL3::SSL::Context ctx, const char *CAfile, const char *CApath)

bool SSL_CTX_set_default_verify_paths(Crypt::OpenSSL3::SSL::Context ctx)

bool SSL_CTX_set_default_verify_dir(Crypt::OpenSSL3::SSL::Context ctx)

bool SSL_CTX_set_default_verify_file(Crypt::OpenSSL3::SSL::Context ctx)

bool SSL_CTX_use_certificate(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::X509 x)

bool SSL_CTX_use_certificate_ASN1(Crypt::OpenSSL3::SSL::Context ctx, int length(d), unsigned char *d)

bool SSL_CTX_use_certificate_file(Crypt::OpenSSL3::SSL::Context ctx, const char *file, int type)

bool SSL_CTX_use_certificate_chain_file(Crypt::OpenSSL3::SSL::Context ctx, const char *file)

long SSL_CTX_add_extra_chain_cert(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::X509 x509)

long SSL_CTX_clear_extra_chain_certs(Crypt::OpenSSL3::SSL::Context ctx)

bool SSL_CTX_use_PrivateKey(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::PrivateKey pkey)

bool SSL_CTX_use_PrivateKey_ASN1(int pk, Crypt::OpenSSL3::SSL::Context ctx, unsigned char *d, long length(d))

bool SSL_CTX_use_PrivateKey_file(Crypt::OpenSSL3::SSL::Context ctx, const char *file, int type)

void SSL_CTX_set_verify(Crypt::OpenSSL3::SSL::Context ctx, int mode)
C_ARGS:
	ctx, mode, NULL

void SSL_CTX_set_verify_depth(Crypt::OpenSSL3::SSL::Context ctx, int depth)

void SSL_CTX_set_post_handshake_auth(Crypt::OpenSSL3::SSL::Context ctx, int val)

bool SSL_CTX_set_cipher_list(Crypt::OpenSSL3::SSL::Context ctx, const char *str)

bool SSL_CTX_set_ciphersuites(Crypt::OpenSSL3::SSL::Context ctx, const char *str)

int SSL_CTX_add_client_CA(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::X509 cacert)
POSTCALL:
	X509_up_ref(cacert);

bool SSL_CTX_add_session(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::SSL::Session c);

bool SSL_CTX_remove_session(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::SSL::Session c);



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::SSL	PREFIX = SSL_

BOOT:
{
	HV* stash = get_hv("Crypt::OpenSSL3::SSL", FALSE);
	CONSTANT2(SSL_, ERROR_NONE);
	CONSTANT2(SSL_, ERROR_ZERO_RETURN);
	CONSTANT2(SSL_, ERROR_WANT_READ);
	CONSTANT2(SSL_, ERROR_WANT_WRITE);
	CONSTANT2(SSL_, ERROR_WANT_CONNECT);
	CONSTANT2(SSL_, ERROR_WANT_ACCEPT);
	CONSTANT2(SSL_, ERROR_WANT_X509_LOOKUP);
	CONSTANT2(SSL_, ERROR_WANT_ASYNC);
	CONSTANT2(SSL_, ERROR_WANT_ASYNC_JOB);
	CONSTANT2(SSL_, ERROR_SYSCALL);
	CONSTANT2(SSL_, ERROR_SSL);

	CONSTANT2(SSL_, VERIFY_NONE);
	CONSTANT2(SSL_, VERIFY_PEER);
	CONSTANT2(SSL_, VERIFY_FAIL_IF_NO_PEER_CERT);
	CONSTANT2(SSL_, VERIFY_CLIENT_ONCE);
	CONSTANT2(SSL_, VERIFY_POST_HANDSHAKE);

	CONSTANT2(SSL_, MODE_ENABLE_PARTIAL_WRITE);
	CONSTANT2(SSL_, MODE_ACCEPT_MOVING_WRITE_BUFFER);
	CONSTANT2(SSL_, MODE_AUTO_RETRY);
	CONSTANT2(SSL_, MODE_RELEASE_BUFFERS);
	CONSTANT2(SSL_, MODE_SEND_FALLBACK_SCSV);
	CONSTANT2(SSL_, MODE_ASYNC);

	CONSTANT2(, TLS1_1_VERSION);
	CONSTANT2(, TLS1_2_VERSION);
	CONSTANT2(, TLS1_3_VERSION);
}

Crypt::OpenSSL3::SSL SSL_new(SV* class, Crypt::OpenSSL3::SSL::Context context)
C_ARGS:
	context

Crypt::OpenSSL3::SSL::Protocol SSL_get_ssl_method(Crypt::OpenSSL3::SSL ssl)

long SSL_set_options(Crypt::OpenSSL3::SSL ctx, long options)

long SSL_clear_options(Crypt::OpenSSL3::SSL ctx, long options)

long SSL_get_options(Crypt::OpenSSL3::SSL ctx)

bool SSL_set_session_id_context(Crypt::OpenSSL3::SSL ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len)

long SSL_set_mode(Crypt::OpenSSL3::SSL ctx, long mode)

long SSL_clear_mode(Crypt::OpenSSL3::SSL ctx, long mode)

long SSL_get_mode(Crypt::OpenSSL3::SSL ctx)

bool SSL_set_min_proto_version(Crypt::OpenSSL3::SSL ctx, int version)

bool SSL_set_max_proto_version(Crypt::OpenSSL3::SSL ctx, int version)

bool SSL_set_alpn_protos(Crypt::OpenSSL3::SSL ctx, const unsigned char *protos, unsigned int protos_len)

bool SSL_use_certificate(Crypt::OpenSSL3::SSL ctx, Crypt::OpenSSL3::X509 x)

bool SSL_use_certificate_ASN1(Crypt::OpenSSL3::SSL ctx, const char *d, int length(d))

bool SSL_use_certificate_file(Crypt::OpenSSL3::SSL ctx, const char *file, int type)

bool SSL_use_certificate_chain_file(Crypt::OpenSSL3::SSL ctx, const char *file)

bool SSL_use_PrivateKey(Crypt::OpenSSL3::SSL ctx, Crypt::OpenSSL3::PrivateKey pkey)

bool SSL_use_PrivateKey_ASN1(int pk, Crypt::OpenSSL3::SSL ctx, const char *d, long length(d))

bool SSL_use_PrivateKey_file(Crypt::OpenSSL3::SSL ctx, const char *file, int type)

void SSL_set_verify(Crypt::OpenSSL3::SSL ctx, int mode)
C_ARGS:
	ctx, mode, NULL

void SSL_set_verify_depth(Crypt::OpenSSL3::SSL ctx, int depth)

Crypt::OpenSSL3::X509::VerifyResult SSL_get_verify_result(Crypt::OpenSSL3::SSL ssl);

void SSL_set_post_handshake_auth(Crypt::OpenSSL3::SSL ctx, int val)

bool SSL_set_cipher_list(Crypt::OpenSSL3::SSL ctx, const char *str)

bool SSL_set_ciphersuites(Crypt::OpenSSL3::SSL ctx, const char *str)

int SSL_add_client_CA(Crypt::OpenSSL3::SSL ctx, Crypt::OpenSSL3::X509 cacert)
POSTCALL:
	X509_up_ref(cacert);

bool SSL_verify_client_post_handshake(Crypt::OpenSSL3::SSL ssl)

int SSL_get_error(Crypt::OpenSSL3::SSL ssl, int ret)

bool SSL_set_tlsext_host_name(Crypt::OpenSSL3::SSL s, const char *name)

const char* SSL_get_servername(Crypt::OpenSSL3::SSL s, int type)

int SSL_get_servername_type(Crypt::OpenSSL3::SSL s)

bool SSL_set_host(Crypt::OpenSSL3::SSL s, const char *hostname)

int SSL_connect(Crypt::OpenSSL3::SSL ssl)

int SSL_accept(Crypt::OpenSSL3::SSL ssl)

int SSL_clear(Crypt::OpenSSL3::SSL ssl)

int SSL_do_handshake(Crypt::OpenSSL3::SSL ssl)

void SSL_set_connect_state(Crypt::OpenSSL3::SSL ssl)

void SSL_set_accept_state(Crypt::OpenSSL3::SSL ssl)

bool SSL_is_server(Crypt::OpenSSL3::SSL ssl)

int SSL_read(Crypt::OpenSSL3::SSL ssl, SV* buffer, size_t size)
INIT:
	char* ptr = grow_buffer(buffer, size);
C_ARGS:
	ssl, ptr, size
POSTCALL:
	set_buffer_length(buffer, RETVAL);

int SSL_peek(Crypt::OpenSSL3::SSL ssl, SV* buffer, size_t size)
INIT:
	char* ptr = grow_buffer(buffer, size);
C_ARGS:
	ssl, ptr, size
POSTCALL:
	set_buffer_length(buffer, RETVAL);

int SSL_write(Crypt::OpenSSL3::SSL ssl, const char* buf, int length(buf))

int SSL_shutdown(Crypt::OpenSSL3::SSL ssl)

bool SSL_set_fd(Crypt::OpenSSL3::SSL ssl, int fd)

bool SSL_set_rfd(Crypt::OpenSSL3::SSL ssl, int fd)

bool SSL_set_wfd(Crypt::OpenSSL3::SSL ssl, int fd)

int SSL_get_fd(Crypt::OpenSSL3::SSL ssl)

int SSL_get_rfd(Crypt::OpenSSL3::SSL ssl)

int SSL_get_wfd(Crypt::OpenSSL3::SSL ssl)

void SSL_set_rbio(Crypt::OpenSSL3::SSL s, Crypt::OpenSSL3::BIO bio)
POSTCALL:
	BIO_up_ref(bio);

void SSL_set_wbio(Crypt::OpenSSL3::SSL s, Crypt::OpenSSL3::BIO bio);
POSTCALL:
	BIO_up_ref(bio);

Crypt::OpenSSL3::SSL::Session SSL_get_session(Crypt::OpenSSL3::SSL ssl)
POSTCALL:
	SSL_SESSION_up_ref(RETVAL);

bool SSL_set_session(Crypt::OpenSSL3::SSL ssl, Crypt::OpenSSL3::SSL::Session session)

bool SSL_session_reused(Crypt::OpenSSL3::SSL ssl)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::SSL::Session	PREFIX = SSL_SESSION_

Crypt::OpenSSL3::X509 SSL_SESSION_get_peer(Crypt::OpenSSL3::SSL::Session session)
POSTCALL:
	X509_up_ref(RETVAL);


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Cipher	PREFIX = EVP_CIPHER_

Crypt::OpenSSL3::Cipher EVP_CIPHER_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS:
	NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

int EVP_CIPHER_get_nid(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_block_size(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_key_length(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_iv_length(Crypt::OpenSSL3::Cipher e)

unsigned long EVP_CIPHER_get_mode(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_type(Crypt::OpenSSL3::Cipher ctx)

int EVP_CIPHER_is_a(Crypt::OpenSSL3::Cipher cipher, const char *name)

const char *EVP_CIPHER_get_name(Crypt::OpenSSL3::Cipher cipher)

const char *EVP_CIPHER_get_description(Crypt::OpenSSL3::Cipher cipher)

bool EVP_CIPHER_names_do_all(Crypt::OpenSSL3::Cipher cipher, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	cipher, EVP_name_callback, &data

void EVP_CIPHER_do_all_provided(SV* class, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	NULL, EVP_CIPHER_provided_callback, &data

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Cipher::Context	PREFIX = EVP_CIPHER_CTX_

Crypt::OpenSSL3::Cipher::Context EVP_CIPHER_CTX_new(SV* class)
C_ARGS:

bool init(Crypt::OpenSSL3::Cipher::Context ctx, Crypt::OpenSSL3::Cipher cipher, const unsigned char* key, const unsigned char* iv, int enc, SV* args = undef)
CODE:
	const OSSL_PARAM* params = params_for(EVP_CIPHER_settable_ctx_params(cipher), args);
	RETVAL = EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, params);
OUTPUT:
	RETVAL

bool update(Crypt::OpenSSL3::Cipher::Context ctx, SV* output, const char* input, size_t length(input))
CODE:
	char* ptr = grow_buffer(output, STRLEN_length_of_input);
	int outl = STRLEN_length_of_input;
	RETVAL = EVP_CipherUpdate(ctx, ptr, &outl, input, STRLEN_length_of_input);
	if (RETVAL)
		set_buffer_length(output, outl);
OUTPUT:
	RETVAL

bool final(Crypt::OpenSSL3::Cipher::Context ctx, SV* output, int size = -1)
CODE:
	if (size == -1)
		size = EVP_CIPHER_CTX_get_block_size(ctx);
	char* ptr = grow_buffer(output, size);
	RETVAL = EVP_CipherFinal_ex(ctx, ptr, &size);
	if (RETVAL)
		set_buffer_length(output, size);
OUTPUT:
	RETVAL

int EVP_CIPHER_CTX_get_nid(Crypt::OpenSSL3::Cipher::Context e)

int EVP_CIPHER_CTX_get_block_size(Crypt::OpenSSL3::Cipher::Context e)

int EVP_CIPHER_CTX_get_key_length(Crypt::OpenSSL3::Cipher::Context e)

int EVP_CIPHER_CTX_get_iv_length(Crypt::OpenSSL3::Cipher::Context e)

unsigned long EVP_CIPHER_CTX_get_mode(Crypt::OpenSSL3::Cipher::Context e)

int EVP_CIPHER_CTX_type(Crypt::OpenSSL3::Cipher::Context ctx)

bool EVP_CIPHER_CTX_set_padding(Crypt::OpenSSL3::Cipher::Context ctx, int padding)

bool EVP_CIPHER_CTX_set_key_length(Crypt::OpenSSL3::Cipher::Context ctx, int keylen)

int EVP_CIPHER_CTX_ctrl(Crypt::OpenSSL3::Cipher::Context ctx, int cmd, int p1, char *p2)

bool EVP_CIPHER_CTX_rand_key(Crypt::OpenSSL3::Cipher::Context ctx, unsigned char *key)

Crypt::OpenSSL3::Cipher EVP_CIPHER_CTX_get_cipher(Crypt::OpenSSL3::Cipher::Context ctx)

const char *EVP_CIPHER_CTX_get_name(Crypt::OpenSSL3::Cipher::Context ctx)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MD	PREFIX = EVP_MD_

Crypt::OpenSSL3::MD EVP_MD_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS:
	NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

const char *EVP_MD_get_name(Crypt::OpenSSL3::MD md)

const char *EVP_MD_get_description(Crypt::OpenSSL3::MD md)

bool EVP_MD_is_a(Crypt::OpenSSL3::MD md, const char *name)

bool EVP_MD_names_do_all(Crypt::OpenSSL3::MD md, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	md, EVP_name_callback, &data

void EVP_MD_do_all_provided(SV* class, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	NULL, EVP_MD_provided_callback, &data

int EVP_MD_get_type(Crypt::OpenSSL3::MD md)

int EVP_MD_get_pkey_type(Crypt::OpenSSL3::MD md)

int EVP_MD_get_size(Crypt::OpenSSL3::MD md)

int EVP_MD_get_block_size(Crypt::OpenSSL3::MD md)

unsigned long EVP_MD_get_flags(Crypt::OpenSSL3::MD md)

bool EVP_MD_xof(Crypt::OpenSSL3::MD md)



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MD::Context	PREFIX = EVP_MD_CTX_

Crypt::OpenSSL3::MD::Context EVP_MD_CTX_new(SV* class)
C_ARGS:

bool EVP_MD_CTX_reset(Crypt::OpenSSL3::MD::Context ctx)

bool EVP_MD_CTX_init(Crypt::OpenSSL3::MD::Context ctx, Crypt::OpenSSL3::MD type, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_MD_CTX_settable_params(ctx), args);
C_ARGS:
	ctx, type, params

bool EVP_MD_CTX_update(Crypt::OpenSSL3::MD::Context ctx, const char *d, size_t length(d))

bool EVP_MD_CTX_final(Crypt::OpenSSL3::MD::Context ctx, SV* buffer)
INIT:
	unsigned int size = EVP_MD_CTX_size(ctx);
	char* ptr = grow_buffer(buffer, size);
C_ARGS:
	ctx, ptr, &size
POSTCALL:
	if (RETVAL)
		set_buffer_length(buffer, size);

bool EVP_MD_CTX_final_xof(Crypt::OpenSSL3::MD::Context ctx, SV* buffer, size_t outlen)
INIT:
	char* ptr = grow_buffer(buffer, outlen);
C_ARGS:
	ctx, ptr, outlen
POSTCALL:
	if (RETVAL)
		set_buffer_length(buffer, outlen);

bool EVP_MD_CTX_squeeze(Crypt::OpenSSL3::MD::Context ctx, SV* buffer, size_t outlen)
INIT:
	char* ptr = grow_buffer(buffer, outlen);
C_ARGS:
	ctx, ptr, outlen
POSTCALL:
	if (RETVAL)
		set_buffer_length(buffer, outlen);

void EVP_MD_CTX_ctrl(Crypt::OpenSSL3::MD::Context ctx, int cmd, int p1, char* p2);

void EVP_MD_CTX_set_flags(Crypt::OpenSSL3::MD::Context ctx, int flags)

void EVP_MD_CTX_clear_flags(Crypt::OpenSSL3::MD::Context ctx, int flags)

int EVP_MD_CTX_test_flags(Crypt::OpenSSL3::MD::Context ctx, int flags)

Crypt::OpenSSL3::MD EVP_MD_CTX_get_md(Crypt::OpenSSL3::MD::Context ctx)

const char *EVP_MD_CTX_get_name(Crypt::OpenSSL3::MD::Context ctx)

int EVP_MD_CTX_get_size(Crypt::OpenSSL3::MD::Context ctx)

int EVP_MD_CTX_get_size_ex(Crypt::OpenSSL3::MD::Context ctx)

int EVP_MD_CTX_get_block_size(Crypt::OpenSSL3::MD::Context ctx)

int EVP_MD_CTX_get_type(Crypt::OpenSSL3::MD::Context ctx)



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MAC	PREFIX = EVP_MAC_

Crypt::OpenSSL3::MAC EVP_MAC_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS:
	NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

const char *EVP_MAC_get_name(Crypt::OpenSSL3::MAC mac)

const char *EVP_MAC_get_description(Crypt::OpenSSL3::MAC mac)

bool EVP_MAC_is_a(Crypt::OpenSSL3::MAC mac, const char *name)

bool EVP_MAC_names_do_all(Crypt::OpenSSL3::MAC mac, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	mac, EVP_name_callback, &data

void EVP_MAC_do_all_provided(SV* class, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	NULL, EVP_MAC_provided_callback, &data



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MAC::Context	PREFIX = EVP_MAC_CTX_

Crypt::OpenSSL3::MAC::Context EVP_MAC_CTX_new(SV* class, Crypt::OpenSSL3::MAC ctx)
C_ARGS:
	ctx

Crypt::OpenSSL3::MAC EVP_MAC_CTX_get_mac(Crypt::OpenSSL3::MAC::Context ctx);
POSTCALL:
	EVP_MAC_up_ref(RETVAL);

size_t EVP_MAC_CTX_get_mac_size(Crypt::OpenSSL3::MAC::Context ctx)

size_t EVP_MAC_CTX_get_block_size(Crypt::OpenSSL3::MAC::Context ctx)


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MAC::Context	PREFIX = EVP_MAC_

bool EVP_MAC_init(Crypt::OpenSSL3::MAC::Context ctx, const unsigned char *key, size_t length(key), SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_MAC_CTX_settable_params(ctx), args);
C_ARGS:
	ctx, key, STRLEN_length_of_key, params

bool EVP_MAC_update(Crypt::OpenSSL3::MAC::Context ctx, const unsigned char *data, size_t length(data))

bool EVP_MAC_final(Crypt::OpenSSL3::MAC::Context ctx, SV* buffer, ssize_t outsize = -1)
CODE:
	if (outsize == -1)
		EVP_MAC_final(ctx, NULL, &outsize, 0);
	char* ptr = grow_buffer(buffer, outsize);
	RETVAL = EVP_MAC_final(ctx, ptr, &outsize, outsize);
	if (RETVAL)
		set_buffer_length(buffer, outsize);
OUTPUT:
	RETVAL

int EVP_MAC_finalXOF(Crypt::OpenSSL3::MAC::Context ctx, SV* buffer, size_t outsize)
INIT:
	char* ptr = grow_buffer(buffer, outsize);
C_ARGS:
	ctx, ptr, outsize
POSTCALL:
	if (RETVAL)
		set_buffer_length(buffer, outsize);



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::KDF	PREFIX = EVP_KDF_

Crypt::OpenSSL3::KDF EVP_KDF_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS:
	NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

const char *EVP_KDF_get_name(Crypt::OpenSSL3::KDF kdf)

const char *EVP_KDF_get_description(Crypt::OpenSSL3::KDF kdf)

bool EVP_KDF_is_a(Crypt::OpenSSL3::KDF kdf, const char *name)

bool EVP_KDF_names_do_all(Crypt::OpenSSL3::KDF kdf, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	kdf, EVP_name_callback, &data

void EVP_KDF_do_all_provided(SV* class, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	NULL, EVP_KDF_provided_callback, &data

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::KDF::Context	PREFIX = EVP_KDF_CTX_

Crypt::OpenSSL3::KDF::Context EVP_KDF_CTX_new(SV* class, Crypt::OpenSSL3::KDF ctx)
C_ARGS:
	ctx

size_t EVP_KDF_CTX_get_kdf_size(Crypt::OpenSSL3::KDF::Context ctx)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::KDF::Context	PREFIX = EVP_KDF_

bool EVP_KDF_derive(Crypt::OpenSSL3::KDF::Context ctx, SV* buffer, size_t keylen, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_KDF_CTX_settable_params(ctx), args);
	char* ptr = grow_buffer(buffer, keylen);
C_ARGS:
	ctx, ptr, keylen, params
POSTCALL:
	if (RETVAL)
		set_buffer_length(buffer, keylen);
