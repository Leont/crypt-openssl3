#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/ssl.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

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

typedef unsigned long Crypt__OpenSSL3__Error;
COUNTING_TYPE(EVP_RAND, Random)
COUNTING_TYPE(EVP_RAND_CTX, Random__Context)
COUNTING_TYPE(EVP_CIPHER, Cipher)
DUPLICATING_TYPE(EVP_CIPHER_CTX, Cipher__Context)
COUNTING_TYPE(EVP_MD, MD)
DUPLICATING_TYPE(EVP_MD_CTX, MD__Context)
COUNTING_TYPE(EVP_MAC, MAC)
DUPLICATING_TYPE(EVP_MAC_CTX, MAC__Context)
COUNTING_TYPE(EVP_KDF, KDF)
DUPLICATING_TYPE(EVP_KDF_CTX, KDF__Context)
COUNTING_TYPE(EVP_SIGNATURE, Signature)
COUNTING_TYPE(EVP_PKEY, PKey)
DUPLICATING_TYPE(EVP_PKEY_CTX, PKey__Context)

typedef BIGNUM BN;
DUPLICATING_TYPE(BN, BigNum);
#define BN_CTX_dup(old) BN_CTX_new()
DUPLICATING_TYPE(BN_CTX, BigNum__Context)
SIMPLE_TYPE(ASN1_OBJECT, ASN1__Object, )
COUNTING_TYPE(X509, X509)
COUNTING_TYPE(X509_STORE, X509__Store)
DUPLICATING_TYPE(X509_NAME, X509__Name)
DUPLICATING_TYPE(X509_NAME_ENTRY, X509__Name__Entry)
typedef long Crypt__OpenSSL3__X509__VerifyResult;

COUNTING_TYPE(BIO, BIO)

SIMPLE_TYPE(SSL_METHOD, SSL__Method, const)
COUNTING_TYPE(SSL_CTX, SSL__Context)
COUNTING_TYPE(SSL, SSL)
COUNTING_TYPE(SSL_SESSION, SSL__Session)

static SV* S_make_object(pTHX_ void* var, const MGVTBL* mgvtbl, const char* ntype) {
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

#define SSL_set_host SSL_set1_host
#define SSL_set_rbio SSL_set0_rbio
#define SSL_set_wbio SSL_set0_wbio

#define SSL_SESSION_get_peer SSL_SESSION_get0_peer

#define RAND_get_primary(class) RAND_get0_primary(NULL)
#define RAND_get_public(class) RAND_get0_public(NULL)
#define RAND_get_private(class) RAND_get0_private(NULL)
#define RAND_set_public(class, rand) RAND_set0_public(NULL, rand)
#define RAND_set_private(class, rand) RAND_set0_private(NULL, rand)
#define EVP_RAND_get_name EVP_RAND_get0_name
#define EVP_RAND_get_description EVP_RAND_get0_description
#define EVP_RAND_CTX_get_rand EVP_RAND_CTX_get0_rand
#define EVP_CIPHER_get_name EVP_CIPHER_get0_name
#define EVP_CIPHER_get_description EVP_CIPHER_get0_description
#define EVP_CIPHER_CTX_set_aead_ivlen(ctx, length) EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, length, NULL)
#define EVP_CIPHER_CTX_get_aead_tag(ctx, ptr, length) EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, length, ptr)
#define EVP_CIPHER_CTX_set_aead_tag(ctx, ptr, length) EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, length, ptr)
#define EVP_CIPHER_CTX_get_name EVP_CIPHER_CTX_get0_name
#define EVP_CIPHER_CTX_get_cipher EVP_CIPHER_CTX_get1_cipher

#define EVP_MD_digest EVP_Digest
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

#define EVP_SIGNATURE_get_name EVP_SIGNATURE_get0_name
#define EVP_SIGNATURE_get_description EVP_SIGNATURE_get0_description

#define EVP_PKEY_get_description EVP_PKEY_get0_description
#define EVP_PKEY_get_type_name EVP_PKEY_get0_type_name
#define EVP_PKEY_get_encoded_public_key EVP_PKEY_get1_encoded_public_key
#define EVP_PKEY_set_encoded_public_key EVP_PKEY_set1_encoded_public_key
#define EVP_PKEY_encrypt_init EVP_PKEY_encrypt_init_ex
#define EVP_PKEY_decrypt_init EVP_PKEY_decrypt_init_ex
#define EVP_PKEY_derive_init EVP_PKEY_derive_init_ex
#define EVP_PKEY_derive_set_peer EVP_PKEY_derive_set_peer_ex
#define EVP_PKEY_sign_init EVP_PKEY_sign_init_ex2
#define EVP_PKEY_verify_init EVP_PKEY_verify_init_ex2
#define EVP_PKEY_CTX_add_hkdf_info EVP_PKEY_CTX_add1_hkdf_info
#define EVP_PKEY_CTX_set_hkdf_salt EVP_PKEY_CTX_set1_hkdf_salt
#define EVP_PKEY_CTX_set_hkdf_key EVP_PKEY_CTX_set1_hkdf_key
#define EVP_PKEY_CTX_get_dh_kdf_oid EVP_PKEY_CTX_get0_dh_kdf_oid
#define EVP_PKEY_CTX_set_dh_kdf_oid EVP_PKEY_CTX_set0_dh_kdf_oid
#define EVP_PKEY_CTX_get_rsa_oaep_label EVP_PKEY_CTX_get0_rsa_oaep_label
#define EVP_PKEY_CTX_set_rsa_oaep_label EVP_PKEY_CTX_set0_rsa_oaep_label
#define EVP_PKEY_CTX_set_id EVP_PKEY_CTX_set1_id

#define CONSTANT2(PREFIX, VALUE) newCONSTSUB(stash, #VALUE, newSVuv(PREFIX##VALUE))

static char* S_make_buffer(pTHX_ SV** retval, size_t size) {
	*retval = newSVpv(NULL, 0);
	char* ptr = SvGROW(*retval, size);
	return ptr;
}
#define make_buffer(svp, size) S_make_buffer(aTHX_ svp, size)

static char* S_grow_buffer(pTHX_ SV* buffer, size_t size) {
	SvUPGRADE(buffer, SVt_PV);
	SV_CHECK_THINKFIRST(buffer);
	return SvGROW(buffer, size);
}
#define grow_buffer(sv, size) S_grow_buffer(aTHX_ sv, size)

static inline void S_set_buffer_length(pTHX_ SV* buffer, ssize_t result) {
	SvCUR_set(buffer, result);
	SvPOK_only(buffer);
}
#define set_buffer_length(buffer, result) S_set_buffer_length(aTHX_ buffer, result)

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

static OSSL_PARAM* S_params_dup(pTHX_ const OSSL_PARAM* input) {
	size_t counter = 0;
	for (const OSSL_PARAM* iter = input; iter->key; iter++)
		counter++;

	OSSL_PARAM* result = OPENSSL_zalloc((counter + 1) * sizeof(OSSL_PARAM));

	for (size_t index = 0; index < counter; ++index) {
		result[index].key = input[index].key;
		result[index].data_type = input[index].data_type;
		result[index].data = NULL;
		result[index].data_size = SIZE_MAX;
		result[index].return_size = 0;
	}
	result[counter].key = NULL;
	result[counter].data_type = 0;

	SAVEDESTRUCTOR(OSSL_PARAM_free, result);

	return result;
}
#define params_dup(params) S_params_dup(aTHX_ params)


static HV* S_reallocate_get_params(pTHX_ OSSL_PARAM* gettable) {
	HV* hash = newHV();

	while (gettable->key) {
		SV* sv = NULL;
		if (gettable->data_type == OSSL_PARAM_INTEGER) {
			sv = newSViv(0);
			gettable->data_size = IVSIZE;
			gettable->data = &SvIVX(sv);
		}
		else if (gettable->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
			sv = newSVuv(UV_MAX);
			gettable->data_size = UVSIZE;
			gettable->data = &SvIVX(sv);
		}
		else if (gettable->data_type == OSSL_PARAM_REAL) {
			sv = newSVnv(0);
			gettable->data_size = NVSIZE;
			gettable->data = &SvNVX(sv);
		}
		else if (gettable->data_type == OSSL_PARAM_UTF8_STRING) {
			sv = newSV(gettable->return_size ? gettable->return_size : 1);
			SvCUR_set(sv, gettable->return_size);
			SvUTF8_on(sv);
			SvPOK_only_UTF8(sv);
			gettable->data_size = gettable->return_size + 1;
			gettable->data = SvPVX(sv);
		}
		else if (gettable->data_type == OSSL_PARAM_OCTET_STRING) {
			sv = newSV(gettable->return_size);
			SvCUR_set(sv, gettable->return_size);
			SvPOK_only(sv);
			gettable->data_size = gettable->return_size;
			gettable->data = SvPVX(sv);
		}

		if (sv)
			hv_store(hash, gettable->key, strlen(gettable->key), sv, 0);

		gettable++;
	}
	sv_2mortal((SV*)hash);

	return hash;
}
#define reallocate_get_params(params) S_reallocate_get_params(aTHX_ params)

#define GENERATE_GET_PARAMS(prefix, arg)\
	RETVAL = &PL_sv_undef;\
	OSSL_PARAM* params = params_dup(prefix ## _gettable_params(arg));\
	if (prefix ## _get_params(arg, params)) {\
		HV* hash = reallocate_get_params(params);\
		if (prefix ## _get_params(arg, params))\
			RETVAL = newRV_inc((SV*)hash);\
	}

#ifdef MULTIPLICITY
#define iTHX aTHX
#else
#define iTHX NULL
#endif

static void EVP_name_callback(const char* name, void* vdata) {
	dTHXa((PerlInterpreter*)vdata);
	dSP;
	mXPUSHp(name, strlen(name));
	PUTBACK;
}

#define DEFINE_PROVIDED_CALLBACK(c_type, name)\
static void c_type ## _provided_callback(c_type* provided, void* vdata) {\
	dTHXa((PerlInterpreter*)vdata);\
	c_type ## _up_ref(provided);\
	SV* object = make_object(provided, &Crypt__OpenSSL3__ ## name ## _magic, "Crypt::OpenSSL3::" #name);\
	dSP;\
	mXPUSHs(object);\
	PUTBACK;\
}
DEFINE_PROVIDED_CALLBACK(EVP_RAND, Random)
DEFINE_PROVIDED_CALLBACK(EVP_CIPHER, Cipher)
DEFINE_PROVIDED_CALLBACK(EVP_MD, MD)
DEFINE_PROVIDED_CALLBACK(EVP_MAC, MAC)
DEFINE_PROVIDED_CALLBACK(EVP_KDF, KDF)
DEFINE_PROVIDED_CALLBACK(EVP_SIGNATURE, Signature)

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

Crypt::OpenSSL3::Random T_MAGICEXT
Crypt::OpenSSL3::Random::Context T_MAGICEXT
Crypt::OpenSSL3::Cipher T_MAGICEXT
Crypt::OpenSSL3::Cipher::Context T_MAGICEXT
Crypt::OpenSSL3::MD T_MAGICEXT
Crypt::OpenSSL3::MD::Context T_MAGICEXT
Crypt::OpenSSL3::MAC T_MAGICEXT
Crypt::OpenSSL3::MAC::Context T_MAGICEXT
Crypt::OpenSSL3::KDF T_MAGICEXT
Crypt::OpenSSL3::KDF::Context T_MAGICEXT
Crypt::OpenSSL3::Signature T_MAGICEXT
Crypt::OpenSSL3::PKey T_MAGICEXT
Crypt::OpenSSL3::PKey::Context T_MAGICEXT

Crypt::OpenSSL3::BIO T_MAGICEXT
Crypt::OpenSSL3::Error T_INTOBJ

Crypt::OpenSSL3::BigNum T_MAGICEXT
Crypt::OpenSSL3::BigNum::Context T_MAGICEXT

Crypt::OpenSSL3::ASN1::Object	T_MAGICEXT
Crypt::OpenSSL3::X509	T_MAGICEXT
Crypt::OpenSSL3::X509::Store	T_MAGICEXT
Crypt::OpenSSL3::X509::Name	T_MAGICEXT
Crypt::OpenSSL3::X509::Name::Entry	T_MAGICEXT
Crypt::OpenSSL3::X509::VerifyResult T_INTOBJ

Crypt::OpenSSL3::SSL::Method T_MAGICEXT
Crypt::OpenSSL3::SSL::Context T_MAGICEXT
Crypt::OpenSSL3::SSL T_MAGICEXT
Crypt::OpenSSL3::SSL::Session T_MAGICEXT
END

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3	PREFIX = ERR_

Crypt::OpenSSL3::Error ERR_get_error(SV* class)
C_ARGS:

Crypt::OpenSSL3::Error ERR_peek_error(SV* class)
C_ARGS:

void ERR_clear_error(SV* class)
C_ARGS:

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Error	PREFIX = ERR_

SV* ERR_error_string(unsigned long e, size_t length = 64)
CODE:
	char* ptr = make_buffer(&RETVAL, length);
	ERR_error_string_n(e, ptr, length);
	set_buffer_length(RETVAL, strlen(ptr));
OUTPUT:
	RETVAL

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::BIO	PREFIX = BIO_

Crypt::OpenSSL3::BIO BIO_new_file(SV* class, const char *filename, const char *mode)
C_ARGS: filename, mode

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

NO_OUTPUT int BIO_read(Crypt::OpenSSL3::BIO b, OUTLIST SV* out, int size)
INIT:
	char* ptr = make_buffer(&out, size);
C_ARGS: b, ptr, size
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(out, RETVAL);

NO_OUTPUT int BIO_gets(Crypt::OpenSSL3::BIO b, OUTLIST SV* out, int size)
INIT:
	char* ptr = make_buffer(&out, size);
C_ARGS: b, ptr, size
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(out, RETVAL);

NO_OUTPUT int BIO_get_line(Crypt::OpenSSL3::BIO b, OUTLIST SV* out, int size)
INIT:
	char* ptr = make_buffer(&out, size);
C_ARGS: b, ptr, size
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(out, RETVAL);

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

NO_OUTPUT int BN_bn2bin(Crypt::OpenSSL3::BigNum a, OUTLIST SV* out)
INIT:
	char* ptr = make_buffer(&out, BN_num_bytes(a));
C_ARGS: a, ptr
POSTCALL:
	set_buffer_length(out, RETVAL);

NO_OUTPUT int BN_bn2binpad(Crypt::OpenSSL3::BigNum a, OUTLIST SV* out, int tolen)
INIT:
	char* ptr = make_buffer(&out, tolen);
C_ARGS: a, ptr, tolen
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(out, RETVAL);

Crypt::OpenSSL3::BigNum BN_bin2bn(const unsigned char *s, int len)
C_ARGS: s, len, NULL


NO_OUTPUT int BN_bn2lebinpad(Crypt::OpenSSL3::BigNum a, OUTLIST SV* out, int tolen)
INIT:
	char* ptr = make_buffer(&out, tolen);
C_ARGS: a, ptr, tolen
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(out, RETVAL);

Crypt::OpenSSL3::BigNum BN_lebin2bn(const unsigned char *s, int len, Crypt::OpenSSL3::BigNum ret)
C_ARGS: s, len, NULL


NO_OUTPUT int BN_bn2nativepad(Crypt::OpenSSL3::BigNum a, OUTLIST SV* out, int tolen)
INIT:
	char* ptr = make_buffer(&out, tolen);
C_ARGS: a, ptr, tolen
POSTCALL:
	if (RETVAL >= 0)
		set_buffer_length(out, RETVAL);

Crypt::OpenSSL3::BigNum BN_native2bn(const unsigned char *s, int len, Crypt::OpenSSL3::BigNum ret)
C_ARGS: s, len, NULL


char *BN_bn2hex(Crypt::OpenSSL3::BigNum a)
CLEANUP:
	OPENSSL_free(RETVAL);

char *BN_bn2dec(Crypt::OpenSSL3::BigNum a)
CLEANUP:
	OPENSSL_free(RETVAL);

int BN_hex2bn(Crypt::OpenSSL3::BigNum a, const char *str)
C_ARGS: &a, str

int BN_dec2bn(Crypt::OpenSSL3::BigNum a, const char *str)
C_ARGS: &a, str

bool BN_print(Crypt::OpenSSL3::BIO fp, Crypt::OpenSSL3::BigNum a)


NO_OUTPUT int BN_bn2mpi(Crypt::OpenSSL3::BigNum a, OUTLIST SV* out)
INIT:
	char* ptr = make_buffer(&out, BN_bn2mpi(a, NULL));
C_ARGS: a, ptr
POSTCALL:
	set_buffer_length(out, RETVAL);

Crypt::OpenSSL3::BigNum BN_mpi2bn(unsigned char *s, int len)
C_ARGS: s, len, NULL

bool BN_check_prime(Crypt::OpenSSL3::BigNum p, Crypt::OpenSSL3::BigNum::Context ctx)
C_ARGS: p, ctx, NULL

bool BN_generate_prime(Crypt::OpenSSL3::BigNum ret, int bits, int safe, Crypt::OpenSSL3::BigNum add, Crypt::OpenSSL3::BigNum rem, Crypt::OpenSSL3::BigNum::Context ctx)
C_ARGS: ret, bits, safe, add, rem, NULL, ctx

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

NO_OUTPUT bool X509_digest(Crypt::OpenSSL3::X509 data, Crypt::OpenSSL3::MD type, OUTLIST SV* digest)
INIT:
	unsigned int output_length = EVP_MD_size(type);
	char* ptr = make_buffer(&digest, output_length);
C_ARGS: data, type, ptr, &output_length
POSTCALL:
	if (RETVAL)
		set_buffer_length(digest, output_length);

NO_OUTPUT bool X509_pubkey_digest(Crypt::OpenSSL3::X509 data, Crypt::OpenSSL3::MD type, OUTLIST SV* digest)
INIT:
	unsigned int output_length = EVP_MD_size(type);
	char* ptr = make_buffer(&digest, output_length);
C_ARGS: data, type, ptr, &output_length
POSTCALL:
	if (RETVAL)
		set_buffer_length(digest, output_length);


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
	C_ARGS: a, NULL, 0
	CLEANUP:
		if (RETVAL)
			OPENSSL_free(RETVAL);

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::X509::Name::Entry	PREFIX = X509_NAME_ENTRY



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::X509::Store	PREFIX = X509_STORE_

bool X509_STORE_add_cert(Crypt::OpenSSL3::X509::Store store, Crypt::OpenSSL3::X509 x)

bool X509_STORE_set_depth(Crypt::OpenSSL3::X509::Store store, int depth)

bool X509_STORE_set_flags(Crypt::OpenSSL3::X509::Store store, unsigned long flags)

bool X509_STORE_set_purpose(Crypt::OpenSSL3::X509::Store store, int purpose)

bool X509_STORE_set_trust(Crypt::OpenSSL3::X509::Store store, int trust)

bool X509_STORE_load_locations(Crypt::OpenSSL3::X509::Store store, const char *file, const char *dir)

bool X509_STORE_set_default_paths(Crypt::OpenSSL3::X509::Store store)


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::SSL::Method	PREFIX = SSL_Method_

Crypt::OpenSSL3::SSL::Method TLS(SV* class)

Crypt::OpenSSL3::SSL::Method TLS_server(SV* class)

Crypt::OpenSSL3::SSL::Method TLS_client(SV* class)

Crypt::OpenSSL3::SSL::Method DTLS(SV* class)

Crypt::OpenSSL3::SSL::Method DTLS_server(SV* class)

Crypt::OpenSSL3::SSL::Method DTLS_client(SV* class)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::SSL::Context	PREFIX = SSL_CTX_

Crypt::OpenSSL3::SSL::Context SSL_CTX_new(SV* class, Crypt::OpenSSL3::SSL::Method method)
C_ARGS: method

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

bool SSL_CTX_use_PrivateKey(Crypt::OpenSSL3::SSL::Context ctx, Crypt::OpenSSL3::PKey pkey)

bool SSL_CTX_use_PrivateKey_ASN1(int pk, Crypt::OpenSSL3::SSL::Context ctx, unsigned char *d, long length(d))

bool SSL_CTX_use_PrivateKey_file(Crypt::OpenSSL3::SSL::Context ctx, const char *file, int type)

void SSL_CTX_set_verify(Crypt::OpenSSL3::SSL::Context ctx, int mode)
C_ARGS: ctx, mode, NULL

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
C_ARGS: context

Crypt::OpenSSL3::SSL::Method SSL_get_ssl_method(Crypt::OpenSSL3::SSL ssl)

long SSL_set_options(Crypt::OpenSSL3::SSL ssl, long options)

long SSL_clear_options(Crypt::OpenSSL3::SSL ssl, long options)

long SSL_get_options(Crypt::OpenSSL3::SSL ssl)

bool SSL_set_session_id_context(Crypt::OpenSSL3::SSL ssl, const unsigned char *sid_ctx, unsigned int sid_ctx_len)

long SSL_set_mode(Crypt::OpenSSL3::SSL ssl, long mode)

long SSL_clear_mode(Crypt::OpenSSL3::SSL ssl, long mode)

long SSL_get_mode(Crypt::OpenSSL3::SSL ssl)

bool SSL_set_min_proto_version(Crypt::OpenSSL3::SSL ssl, int version)

bool SSL_set_max_proto_version(Crypt::OpenSSL3::SSL ssl, int version)

bool SSL_set_alpn_protos(Crypt::OpenSSL3::SSL ssl, const unsigned char *protos, unsigned int protos_len)

bool SSL_use_certificate(Crypt::OpenSSL3::SSL ssl, Crypt::OpenSSL3::X509 x)

bool SSL_use_certificate_ASN1(Crypt::OpenSSL3::SSL ssl, const char *d, int length(d))

bool SSL_use_certificate_file(Crypt::OpenSSL3::SSL ssl, const char *file, int type)

bool SSL_use_certificate_chain_file(Crypt::OpenSSL3::SSL ssl, const char *file)

bool SSL_use_PrivateKey(Crypt::OpenSSL3::SSL ssl, Crypt::OpenSSL3::PKey pkey)

bool SSL_use_PrivateKey_ASN1(int pk, Crypt::OpenSSL3::SSL ssl, const char *d, long length(d))

bool SSL_use_PrivateKey_file(Crypt::OpenSSL3::SSL ssl, const char *file, int type)

void SSL_set_verify(Crypt::OpenSSL3::SSL ssl, int mode)
C_ARGS: ssl, mode, NULL

void SSL_set_verify_depth(Crypt::OpenSSL3::SSL ssl, int depth)

Crypt::OpenSSL3::X509::VerifyResult SSL_get_verify_result(Crypt::OpenSSL3::SSL ssl);

void SSL_set_post_handshake_auth(Crypt::OpenSSL3::SSL ssl, int val)

bool SSL_set_cipher_list(Crypt::OpenSSL3::SSL ssl, const char *str)

bool SSL_set_ciphersuites(Crypt::OpenSSL3::SSL ssl, const char *str)

int SSL_add_client_CA(Crypt::OpenSSL3::SSL ssl, Crypt::OpenSSL3::X509 cacert)
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
C_ARGS: ssl, ptr, size
POSTCALL:
	set_buffer_length(buffer, RETVAL);

int SSL_peek(Crypt::OpenSSL3::SSL ssl, SV* buffer, size_t size)
INIT:
	char* ptr = grow_buffer(buffer, size);
C_ARGS: ssl, ptr, size
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


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Random	PREFIX = EVP_RAND_

Crypt::OpenSSL3::Random EVP_RAND_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS: NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

bool EVP_RAND_is_a(Crypt::OpenSSL3::Random rand, const char *name)

const char *EVP_RAND_get_name(Crypt::OpenSSL3::Random rand)

const char *EVP_RAND_get_description(Crypt::OpenSSL3::Random rand)

void EVP_RAND_names_list_all(Crypt::OpenSSL3::Random rand)
PPCODE:
	PUTBACK;
	EVP_RAND_names_do_all(rand, EVP_name_callback, iTHX);
	SPAGAIN;

void EVP_RAND_list_all_provided(SV* class)
PPCODE:
	PUTBACK;
	EVP_RAND_do_all_provided(NULL, EVP_RAND_provided_callback, iTHX);
	SPAGAIN;

SV* EVP_RAND_get_params(Crypt::OpenSSL3::Random rand)
CODE:
	GENERATE_GET_PARAMS(EVP_RAND, rand)
OUTPUT:
	RETVAL


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Random	PREFIX = RAND_

NO_OUTPUT int RAND_bytes(SV* class, OUTLIST SV* buffer, int num)
INIT:
	char* ptr = make_buffer(&buffer, num);
	set_buffer_length(buffer, num);
C_ARGS: ptr, num

NO_OUTPUT int RAND_priv_bytes(SV* class, OUTLIST SV* buffer, int num);
INIT:
	char* ptr = make_buffer(&buffer, num);
	set_buffer_length(buffer, num);
C_ARGS: ptr, num

Crypt::OpenSSL3::Random::Context RAND_get_primary(SV* class)
POSTCALL:
	EVP_RAND_CTX_up_ref(RETVAL);

Crypt::OpenSSL3::Random::Context RAND_get_public(SV* class)
POSTCALL:
	EVP_RAND_CTX_up_ref(RETVAL);

Crypt::OpenSSL3::Random::Context RAND_get_private(SV* class)
POSTCALL:
	EVP_RAND_CTX_up_ref(RETVAL);

bool RAND_set_public(SV* class, Crypt::OpenSSL3::Random::Context rand)
POSTCALL:
	if (RETVAL)
		EVP_RAND_CTX_up_ref(rand);

bool RAND_set_private(SV* class, Crypt::OpenSSL3::Random::Context rand)
POSTCALL:
	if (RETVAL)
		EVP_RAND_CTX_up_ref(rand);


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Random::Context	PREFIX = EVP_RAND_CTX_

Crypt::OpenSSL3::Random::Context EVP_RAND_CTX_new(SV* class, Crypt::OpenSSL3::Random type, Crypt::OpenSSL3::Random::Context parent = NULL)
C_ARGS: type, parent

Crypt::OpenSSL3::Random EVP_RAND_CTX_get_rand(Crypt::OpenSSL3::Random::Context ctx)

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Random::Context	PREFIX = EVP_RAND_

bool EVP_RAND_instantiate(Crypt::OpenSSL3::Random::Context ctx, unsigned int strength, int prediction_resistance, const unsigned char *pstr, size_t length(pstr), SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_RAND_CTX_settable_params(ctx), args);
C_ARGS: ctx, strength, prediction_resistance, pstr, STRLEN_length_of_pstr, params

bool EVP_RAND_uninstantiate(Crypt::OpenSSL3::Random::Context ctx)

NO_OUTPUT int EVP_RAND_generate(Crypt::OpenSSL3::Random::Context ctx, OUTLIST SV* buffer, size_t outlen, unsigned int strength, int prediction_resistance, const unsigned char *addin, size_t length(addin))
INIT:
	char* ptr = make_buffer(&buffer, outlen);
C_ARGS: ctx, ptr, outlen, strength, prediction_resistance, addin, STRLEN_length_of_addin
POSTCALL:
	if (RETVAL)
		set_buffer_length(buffer, outlen);

int EVP_RAND_reseed(Crypt::OpenSSL3::Random::Context ctx, int prediction_resistance, const unsigned char *ent, size_t ent_len, const unsigned char *addin, size_t addin_len)

NO_OUTPUT int EVP_RAND_nonce(Crypt::OpenSSL3::Random::Context ctx, OUTLIST SV* buffer, size_t outlen)
INIT:
	char* ptr = make_buffer(&buffer, outlen);
C_ARGS: ctx, ptr, outlen
POSTCALL:
	set_buffer_length(buffer, RETVAL);

bool EVP_RAND_enable_locking(Crypt::OpenSSL3::Random::Context ctx)

bool EVP_RAND_verify_zeroization(Crypt::OpenSSL3::Random::Context ctx)

unsigned int EVP_RAND_get_strength(Crypt::OpenSSL3::Random::Context ctx)

int EVP_RAND_get_state(Crypt::OpenSSL3::Random::Context ctx)


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Cipher	PREFIX = EVP_CIPHER_

Crypt::OpenSSL3::Cipher EVP_CIPHER_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS: NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

int EVP_CIPHER_get_nid(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_block_size(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_key_length(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_iv_length(Crypt::OpenSSL3::Cipher e)

unsigned long EVP_CIPHER_get_mode(Crypt::OpenSSL3::Cipher e)

int EVP_CIPHER_get_type(Crypt::OpenSSL3::Cipher cipher)

bool EVP_CIPHER_is_a(Crypt::OpenSSL3::Cipher cipher, const char *name)

const char *EVP_CIPHER_get_name(Crypt::OpenSSL3::Cipher cipher)

const char *EVP_CIPHER_get_description(Crypt::OpenSSL3::Cipher cipher)

void EVP_CIPHER_names_list_all(Crypt::OpenSSL3::Cipher cipher)
PPCODE:
	PUTBACK;
	EVP_CIPHER_names_do_all(cipher, EVP_name_callback, iTHX);
	SPAGAIN;

void EVP_CIPHER_list_all_provided(SV* class)
PPCODE:
	PUTBACK;
	EVP_CIPHER_do_all_provided(NULL, EVP_CIPHER_provided_callback, iTHX);
	SPAGAIN;

SV* EVP_CIPHER_get_params(Crypt::OpenSSL3::Cipher cipher)
CODE:
	GENERATE_GET_PARAMS(EVP_CIPHER, cipher)
OUTPUT:
	RETVAL


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Cipher::Context	PREFIX = EVP_CIPHER_CTX_

Crypt::OpenSSL3::Cipher::Context EVP_CIPHER_CTX_new(SV* class)
C_ARGS:

bool EVP_CIPHER_CTX_reset(Crypt::OpenSSL3::Cipher::Context ctx)

bool init(Crypt::OpenSSL3::Cipher::Context ctx, Crypt::OpenSSL3::Cipher cipher, const unsigned char* key, const unsigned char* iv, int enc, SV* args = undef)
CODE:
	const OSSL_PARAM* params = params_for(EVP_CIPHER_settable_ctx_params(cipher), args);
	RETVAL = EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, params);
OUTPUT:
	RETVAL

SV* update(Crypt::OpenSSL3::Cipher::Context ctx, const char* input, size_t length(input))
CODE:
	int outl = STRLEN_length_of_input;
	char* ptr = make_buffer(&RETVAL, outl);
	bool result = EVP_CipherUpdate(ctx, ptr, &outl, input, STRLEN_length_of_input);
	if (result)
		set_buffer_length(RETVAL, outl);
OUTPUT:
	RETVAL

SV* final(Crypt::OpenSSL3::Cipher::Context ctx)
CODE:
	int size = EVP_CIPHER_CTX_get_block_size(ctx);
	char* ptr = make_buffer(&RETVAL, size);
	int result = EVP_CipherFinal_ex(ctx, ptr, &size);
	if (result)
		set_buffer_length(RETVAL, size);
OUTPUT:
	RETVAL

bool EVP_CIPHER_CTX_set_params(Crypt::OpenSSL3::Cipher::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_CIPHER_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

SV* EVP_CIPHER_CTX_get_params(Crypt::OpenSSL3::Cipher::Context ctx)
CODE:
	GENERATE_GET_PARAMS(EVP_CIPHER_CTX, ctx)
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

NO_OUTPUT bool EVP_CIPHER_CTX_rand_key(Crypt::OpenSSL3::Cipher::Context ctx, OUTLIST SV* key)
INIT:
	size_t size = EVP_CIPHER_CTX_key_length(ctx);
	char* ptr = make_buffer(&key, size);
C_ARGS: ctx, ptr
POSTCALL:
	if (RETVAL)
		set_buffer_length(key, size);

Crypt::OpenSSL3::Cipher EVP_CIPHER_CTX_get_cipher(Crypt::OpenSSL3::Cipher::Context ctx)

const char *EVP_CIPHER_CTX_get_name(Crypt::OpenSSL3::Cipher::Context ctx)

bool EVP_CIPHER_CTX_is_encrypting(Crypt::OpenSSL3::Cipher::Context ctx)

bool EVP_CIPHER_CTX_set_aead_ivlen(Crypt::OpenSSL3::Cipher::Context ctx, int length)

NO_OUTPUT bool EVP_CIPHER_CTX_get_aead_tag(Crypt::OpenSSL3::Cipher::Context ctx, OUTLIST SV* tag, int length)
INIT:
	char* ptr = make_buffer(&tag, length);
C_ARGS: ctx, ptr, length
POSTCALL:
	if (RETVAL)
		set_buffer_length(tag, length);

bool EVP_CIPHER_CTX_set_aead_tag(Crypt::OpenSSL3::Cipher::Context ctx, char* ptr, int length(ptr))


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MD	PREFIX = EVP_MD_

Crypt::OpenSSL3::MD EVP_MD_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS: NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

const char *EVP_MD_get_name(Crypt::OpenSSL3::MD md)

const char *EVP_MD_get_description(Crypt::OpenSSL3::MD md)

bool EVP_MD_is_a(Crypt::OpenSSL3::MD md, const char *name)

void EVP_MD_names_list_all(Crypt::OpenSSL3::MD md)
PPCODE:
	PUTBACK;
	EVP_MD_names_do_all(md, EVP_name_callback, iTHX);
	SPAGAIN;

void EVP_MD_list_all_provided(SV* class)
PPCODE:
	PUTBACK;
	EVP_MD_do_all_provided(NULL, EVP_MD_provided_callback, iTHX);
	SPAGAIN;

int EVP_MD_get_type(Crypt::OpenSSL3::MD md)

int EVP_MD_get_pkey_type(Crypt::OpenSSL3::MD md)

int EVP_MD_get_size(Crypt::OpenSSL3::MD md)

int EVP_MD_get_block_size(Crypt::OpenSSL3::MD md)

unsigned long EVP_MD_get_flags(Crypt::OpenSSL3::MD md)

bool EVP_MD_xof(Crypt::OpenSSL3::MD md)

SV* EVP_MD_get_params(Crypt::OpenSSL3::MD md)
CODE:
	GENERATE_GET_PARAMS(EVP_MD, md)
OUTPUT:
	RETVAL

NO_OUTPUT bool EVP_MD_digest(Crypt::OpenSSL3::MD md, const char* input, size_t length(input), OUTLIST SV* digest)
INIT:
	unsigned int size = EVP_MD_get_size(md);
	char* ptr = make_buffer(&digest, size);
C_ARGS: input, STRLEN_length_of_input, ptr, &size, md, NULL
POSTCALL:
	if (RETVAL)
		set_buffer_length(digest, size);


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MD::Context	PREFIX = EVP_MD_CTX_

Crypt::OpenSSL3::MD::Context EVP_MD_CTX_new(SV* class)
C_ARGS:

bool EVP_MD_CTX_reset(Crypt::OpenSSL3::MD::Context ctx)

bool EVP_MD_CTX_init(Crypt::OpenSSL3::MD::Context ctx, Crypt::OpenSSL3::MD type, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_MD_CTX_settable_params(ctx), args);
C_ARGS: ctx, type, params

bool EVP_MD_CTX_update(Crypt::OpenSSL3::MD::Context ctx, const char *d, size_t length(d))

NO_OUTPUT bool EVP_MD_CTX_final(Crypt::OpenSSL3::MD::Context ctx, OUTLIST SV* digest)
INIT:
	unsigned int size = EVP_MD_CTX_size(ctx);
	char* ptr = make_buffer(&digest , size);
C_ARGS: ctx, ptr, &size
POSTCALL:
	if (RETVAL)
		set_buffer_length(digest, size);

NO_OUTPUT bool EVP_MD_CTX_final_xof(Crypt::OpenSSL3::MD::Context ctx, OUTLIST SV* digest, size_t outlen)
INIT:
	char* ptr = make_buffer(&digest, outlen);
C_ARGS: ctx, ptr, outlen
POSTCALL:
	if (RETVAL)
		set_buffer_length(digest, outlen);

NO_OUTPUT bool EVP_MD_CTX_squeeze(Crypt::OpenSSL3::MD::Context ctx, OUTLIST SV* digest, size_t outlen)
INIT:
	char* ptr = make_buffer(&digest, outlen);
C_ARGS: ctx, ptr, outlen
POSTCALL:
	if (RETVAL)
		set_buffer_length(digest, outlen);

bool EVP_MD_CTX_set_params(Crypt::OpenSSL3::MD::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_MD_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

SV* EVP_MD_CTX_get_params(Crypt::OpenSSL3::MD::Context ctx)
CODE:
	GENERATE_GET_PARAMS(EVP_MD_CTX, ctx)
OUTPUT:
	RETVAL


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
C_ARGS: NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

const char *EVP_MAC_get_name(Crypt::OpenSSL3::MAC mac)

const char *EVP_MAC_get_description(Crypt::OpenSSL3::MAC mac)

bool EVP_MAC_is_a(Crypt::OpenSSL3::MAC mac, const char *name)

void EVP_MAC_names_list_all(Crypt::OpenSSL3::MAC mac, SV* callback)
PPCODE:
	PUTBACK;
	EVP_MAC_names_do_all(mac, EVP_name_callback, iTHX);
	SPAGAIN;

void EVP_MAC_list_all_provided(SV* class)
PPCODE:
	PUTBACK;
	EVP_MAC_do_all_provided(NULL, EVP_MAC_provided_callback, iTHX);
	SPAGAIN;

SV* EVP_MAC_get_params(Crypt::OpenSSL3::MAC mac)
CODE:
	GENERATE_GET_PARAMS(EVP_MAC, mac)
OUTPUT:
	RETVAL



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MAC::Context	PREFIX = EVP_MAC_CTX_

Crypt::OpenSSL3::MAC::Context EVP_MAC_CTX_new(SV* class, Crypt::OpenSSL3::MAC ctx)
C_ARGS: ctx

Crypt::OpenSSL3::MAC EVP_MAC_CTX_get_mac(Crypt::OpenSSL3::MAC::Context ctx);
POSTCALL:
	EVP_MAC_up_ref(RETVAL);

size_t EVP_MAC_CTX_get_mac_size(Crypt::OpenSSL3::MAC::Context ctx)

size_t EVP_MAC_CTX_get_block_size(Crypt::OpenSSL3::MAC::Context ctx)

bool EVP_MAC_CTX_set_params(Crypt::OpenSSL3::MAC::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_MAC_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

SV* EVP_MAC_CTX_get_params(Crypt::OpenSSL3::MAC::Context ctx)
CODE:
	GENERATE_GET_PARAMS(EVP_MAC_CTX, ctx)
OUTPUT:
	RETVAL



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::MAC::Context	PREFIX = EVP_MAC_

bool EVP_MAC_init(Crypt::OpenSSL3::MAC::Context ctx, const unsigned char *key, size_t length(key), SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_MAC_CTX_settable_params(ctx), args);
C_ARGS: ctx, key, STRLEN_length_of_key, params

bool EVP_MAC_update(Crypt::OpenSSL3::MAC::Context ctx, const unsigned char *data, size_t length(data))

NO_OUTPUT bool EVP_MAC_final(Crypt::OpenSSL3::MAC::Context ctx, OUTLIST SV* code, ssize_t outsize = -1)
CODE:
	if (outsize == -1)
		EVP_MAC_final(ctx, NULL, &outsize, 0);
	char* ptr = make_buffer(&code, outsize);
	int result = EVP_MAC_final(ctx, ptr, &outsize, outsize);
	if (result)
		set_buffer_length(code, outsize);

NO_OUTPUT int EVP_MAC_finalXOF(Crypt::OpenSSL3::MAC::Context ctx, OUTLIST SV* code, size_t outsize)
INIT:
	char* ptr = make_buffer(&code, outsize);
C_ARGS: ctx, ptr, outsize
POSTCALL:
	if (RETVAL)
		set_buffer_length(code, outsize);



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::KDF	PREFIX = EVP_KDF_

Crypt::OpenSSL3::KDF EVP_KDF_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS: NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

const char *EVP_KDF_get_name(Crypt::OpenSSL3::KDF kdf)

const char *EVP_KDF_get_description(Crypt::OpenSSL3::KDF kdf)

bool EVP_KDF_is_a(Crypt::OpenSSL3::KDF kdf, const char *name)

void EVP_KDF_names_list_all(Crypt::OpenSSL3::KDF kdf)
PPCODE:
	PUTBACK;
	EVP_KDF_names_do_all(kdf, EVP_name_callback, iTHX);
	SPAGAIN;

void EVP_KDF_list_all_provided(SV* class)
PPCODE:
	PUTBACK;
	EVP_KDF_do_all_provided(NULL, EVP_KDF_provided_callback, iTHX);
	SPAGAIN;

SV* EVP_KDF_get_params(Crypt::OpenSSL3::KDF kdf)
CODE:
	GENERATE_GET_PARAMS(EVP_KDF, kdf)
OUTPUT:
	RETVAL


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::KDF::Context	PREFIX = EVP_KDF_CTX_

Crypt::OpenSSL3::KDF::Context EVP_KDF_CTX_new(SV* class, Crypt::OpenSSL3::KDF ctx)
C_ARGS: ctx

void EVP_KDF_CTX_reset(Crypt::OpenSSL3::KDF::Context ctx)

size_t EVP_KDF_CTX_get_kdf_size(Crypt::OpenSSL3::KDF::Context ctx)

bool EVP_KDF_CTX_set_params(Crypt::OpenSSL3::KDF::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_KDF_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

SV* EVP_KDF_CTX_get_params(Crypt::OpenSSL3::KDF::Context ctx)
CODE:
	GENERATE_GET_PARAMS(EVP_KDF_CTX, ctx)
OUTPUT:
	RETVAL


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::KDF::Context	PREFIX = EVP_KDF_

NO_OUTPUT bool EVP_KDF_derive(Crypt::OpenSSL3::KDF::Context ctx, OUTLIST SV* derived, size_t keylen, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_KDF_CTX_settable_params(ctx), args);
	char* ptr = make_buffer(&derived, keylen);
C_ARGS: ctx, ptr, keylen, params
POSTCALL:
	if (RETVAL)
		set_buffer_length(derived, keylen);



MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::Signature	PREFIX = EVP_SIGNATURE_

Crypt::OpenSSL3::Signature EVP_SIGNATURE_fetch(SV* class, const char* algorithm, const char* properties = "")
C_ARGS: NULL, algorithm, properties
POSTCALL:
	if (RETVAL == NULL)
		XSRETURN_UNDEF;

const char *EVP_SIGNATURE_get_name(Crypt::OpenSSL3::Signature signature)

const char *EVP_SIGNATURE_get_description(Crypt::OpenSSL3::Signature signature)

bool EVP_SIGNATURE_is_a(Crypt::OpenSSL3::Signature signature, const char *name)

void EVP_SIGNATURE_names_list_all(Crypt::OpenSSL3::Signature signature)
PPCODE:
	PUTBACK;
	EVP_SIGNATURE_names_do_all(signature, EVP_name_callback, iTHX);
	SPAGAIN;

void EVP_SIGNATURE_list_all_provided(SV* class)
PPCODE:
	PUTBACK;
	EVP_SIGNATURE_do_all_provided(NULL, EVP_SIGNATURE_provided_callback, iTHX);
	SPAGAIN;


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::PKey	PREFIX = EVP_PKEY_

Crypt::OpenSSL3::PKey EVP_PKEY_new(SV* class)
C_ARGS:

Crypt::OpenSSL3::PKey EVP_PKEY_new_raw_private_key_ex(SV* class, const char *keytype, const char *propq, const unsigned char *key, size_t length(key))
C_ARGS: NULL, keytype, propq, key, STRLEN_length_of_key

Crypt::OpenSSL3::PKey EVP_PKEY_new_raw_public_key_ex(SV* class, const char *keytype, const char *propq, const unsigned char *key, size_t length(key))
C_ARGS: NULL, keytype, propq, key, STRLEN_length_of_key

NO_OUTPUT void EVP_PKEY_get_raw_private_key(Crypt::OpenSSL3::PKey pkey, OUTLIST SV* key)
CODE:
	size_t length;
	int result = EVP_PKEY_get_raw_private_key(pkey, NULL, &length);
	if (!result)
		XSRETURN_NO;
	char* ptr = make_buffer(&key, length);
	result = EVP_PKEY_get_raw_private_key(pkey, ptr, &length);
	if (result)
		set_buffer_length(key, length);


NO_OUTPUT void EVP_PKEY_get_raw_public_key(Crypt::OpenSSL3::PKey pkey, OUTLIST SV* key)
CODE:
	size_t length;
	int result = EVP_PKEY_get_raw_public_key(pkey, NULL, &length);
	if (!result)
		XSRETURN_NO;
	char* ptr = make_buffer(&key, length);
	result = EVP_PKEY_get_raw_public_key(pkey, ptr, &length);
	if (result)
		set_buffer_length(key, length);

int EVP_PKEY_get_id(Crypt::OpenSSL3::PKey pkey)

int EVP_PKEY_get_base_id(Crypt::OpenSSL3::PKey pkey)

int EVP_PKEY_type(int type)

bool EVP_PKEY_set_type(Crypt::OpenSSL3::PKey pkey, int type)

bool EVP_PKEY_set_type_str(Crypt::OpenSSL3::PKey pkey, const char *str, int len)

int EVP_PKEY_get_size(Crypt::OpenSSL3::PKey pkey)

int EVP_PKEY_get_bits(Crypt::OpenSSL3::PKey pkey)

int EVP_PKEY_get_security_bits(Crypt::OpenSSL3::PKey pkey)

bool EVP_PKEY_is_a(Crypt::OpenSSL3::PKey pkey, const char *name)

bool EVP_PKEY_can_sign(Crypt::OpenSSL3::PKey pkey)

void EVP_PKEY_type_names_list_all(Crypt::OpenSSL3::PKey pkey)
PPCODE:
	PUTBACK;
	EVP_PKEY_type_names_do_all(pkey, EVP_name_callback, iTHX);
	SPAGAIN;

const char *EVP_PKEY_get_type_name(Crypt::OpenSSL3::PKey key)

const char *EVP_PKEY_get_description(Crypt::OpenSSL3::PKey key)

bool EVP_PKEY_digestsign_supports_digest(Crypt::OpenSSL3::PKey pkey, const char *name, const char *propq)
C_ARGS: pkey, NULL, name, propq

NO_OUTPUT int EVP_PKEY_get_default_digest_name(Crypt::OpenSSL3::PKey pkey, OUTLIST SV* mdname)
INIT:
	char* ptr = make_buffer(&mdname, 32);
C_ARGS: pkey, ptr, 32

int EVP_PKEY_get_default_digest_nid(Crypt::OpenSSL3::PKey pkey, OUT int pnid)

int EVP_PKEY_get_field_type(Crypt::OpenSSL3::PKey pkey)

int EVP_PKEY_get_ec_point_conv_form(Crypt::OpenSSL3::PKey pkey)

NO_OUTPUT int EVP_PKEY_get_group_name(Crypt::OpenSSL3::PKey pkey, OUTLIST SV* name, size_t size = 32)
INIT:
	char* ptr = make_buffer(&name, size);
C_ARGS: pkey, ptr, size + 1, &size
POSTCALL:
	if (RETVAL)
		set_buffer_length(name, size);

bool EVP_PKEY_set_encoded_public_key(Crypt::OpenSSL3::PKey pkey, const unsigned char *pub, size_t publen)

size_t EVP_PKEY_get_encoded_public_key(Crypt::OpenSSL3::PKey pkey, OUT unsigned char *ppub)
CLEANUP:
	OPENSSL_free(ppub);

SV* EVP_PKEY_get_params(Crypt::OpenSSL3::PKey pkey)
CODE:
	GENERATE_GET_PARAMS(EVP_PKEY, pkey)
OUTPUT:
	RETVAL

bool EVP_PKEY_get_int_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, OUT int out)

bool EVP_PKEY_get_size_t_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, OUT size_t out)

bool EVP_PKEY_get_bn_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, OUT Crypt::OpenSSL3::BigNum bn)

bool EVP_PKEY_get_utf8_string_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, char *str, size_t length(str), OUT size_t out_len)

bool EVP_PKEY_get_octet_string_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, unsigned char *buf, size_t length(buf), OUT size_t out_len)

bool EVP_PKEY_set_params(Crypt::OpenSSL3::PKey pkey, SV* args = undef)
INIT:
	OSSL_PARAM* params = (OSSL_PARAM*)params_for(EVP_PKEY_settable_params(pkey), args);
C_ARGS: pkey, params

bool EVP_PKEY_set_int_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, int in)

bool EVP_PKEY_set_size_t_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, size_t in)

bool EVP_PKEY_set_bn_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, Crypt::OpenSSL3::BigNum bn)

bool EVP_PKEY_set_utf8_string_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, const char *str)

bool EVP_PKEY_set_octet_string_param(Crypt::OpenSSL3::PKey pkey, const char *key_name, const unsigned char *buf, size_t bsize)

bool EVP_PKEY_print_public(Crypt::OpenSSL3::BIO out, Crypt::OpenSSL3::PKey pkey, int indent)
C_ARGS: out, pkey, indent, NULL

bool EVP_PKEY_print_private(Crypt::OpenSSL3::BIO out, Crypt::OpenSSL3::PKey pkey, int indent)
C_ARGS: out, pkey, indent, NULL

bool EVP_PKEY_print_params(Crypt::OpenSSL3::BIO out, Crypt::OpenSSL3::PKey pkey, int indent)
C_ARGS: out, pkey, indent, NULL

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::PKey::Context	PREFIX = EVP_PKEY_CTX_

Crypt::OpenSSL3::PKey::Context EVP_PKEY_CTX_new(SV* class, Crypt::OpenSSL3::PKey pkey)
C_ARGS: pkey, NULL

Crypt::OpenSSL3::PKey::Context EVP_PKEY_CTX_new_id(SV* class, int id)
C_ARGS: id, NULL

Crypt::OpenSSL3::PKey::Context EVP_PKEY_CTX_new_from_name(SV* class, const char *name, const char *propquery = "")
C_ARGS: NULL, name, propquery

Crypt::OpenSSL3::PKey::Context EVP_PKEY_CTX_new_from_pkey(SV* class, Crypt::OpenSSL3::PKey pkey, const char *propquery = "")
C_ARGS: NULL, pkey, propquery

bool EVP_PKEY_CTX_set_params(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

SV* EVP_PKEY_CTX_get_params(Crypt::OpenSSL3::PKey::Context ctx)
CODE:
	GENERATE_GET_PARAMS(EVP_PKEY_CTX, ctx)
OUTPUT:
	RETVAL


bool EVP_PKEY_CTX_is_a(Crypt::OpenSSL3::PKey::Context ctx, const char *keytype)

bool EVP_PKEY_CTX_set_signature_md(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::MD md)

void EVP_PKEY_CTX_get_signature_md(Crypt::OpenSSL3::PKey::Context ctx, OUTLIST Crypt::OpenSSL3::MD md)
C_ARGS: ctx, (const EVP_MD**)&md

bool EVP_PKEY_CTX_set_mac_key(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *key, int len)

bool EVP_PKEY_CTX_set_group_name(Crypt::OpenSSL3::PKey::Context ctx, const char *name)

NO_OUTPUT bool EVP_PKEY_CTX_get_group_name(Crypt::OpenSSL3::PKey::Context ctx, OUTLIST SV* name, size_t size = 32)
INIT:
	char* ptr = make_buffer(&name, size);
C_ARGS: ctx, ptr, size + 1
POSTCALL:
	if (RETVAL)
		set_buffer_length(name, strlen(ptr));

bool EVP_PKEY_CTX_set_kem_op(Crypt::OpenSSL3::PKey::Context ctx, const char *op)


bool EVP_PKEY_CTX_set_rsa_padding(Crypt::OpenSSL3::PKey::Context ctx, int pad)

bool EVP_PKEY_CTX_get_rsa_padding(Crypt::OpenSSL3::PKey::Context ctx, OUT int pad)

bool EVP_PKEY_CTX_set_rsa_pss_saltlen(Crypt::OpenSSL3::PKey::Context ctx, int saltlen)

bool EVP_PKEY_CTX_get_rsa_pss_saltlen(Crypt::OpenSSL3::PKey::Context ctx, OUT int saltlen)

bool EVP_PKEY_CTX_set_rsa_keygen_bits(Crypt::OpenSSL3::PKey::Context ctx, int mbits)

bool EVP_PKEY_CTX_set_rsa_keygen_primes(Crypt::OpenSSL3::PKey::Context ctx, int primes)

bool EVP_PKEY_CTX_set_rsa_mgf1_md_name(Crypt::OpenSSL3::PKey::Context ctx, const char *mdname, const char *mdprops)

bool EVP_PKEY_CTX_set_rsa_mgf1_md(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::MD md)

bool EVP_PKEY_CTX_get_rsa_mgf1_md(Crypt::OpenSSL3::PKey::Context ctx, OUT Crypt::OpenSSL3::MD md)
C_ARGS: ctx, (const EVP_MD**)&md

bool EVP_PKEY_CTX_get_rsa_mgf1_md_name(Crypt::OpenSSL3::PKey::Context ctx, char *name, size_t namelen)

bool EVP_PKEY_CTX_set_rsa_oaep_md_name(Crypt::OpenSSL3::PKey::Context ctx, const char *mdname, const char *mdprops)

bool EVP_PKEY_CTX_set_rsa_oaep_md(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::MD md)

bool EVP_PKEY_CTX_get_rsa_oaep_md(Crypt::OpenSSL3::PKey::Context ctx, OUT Crypt::OpenSSL3::MD md)
C_ARGS: ctx, (const EVP_MD**)&md

bool EVP_PKEY_CTX_get_rsa_oaep_md_name(Crypt::OpenSSL3::PKey::Context ctx, char *name, size_t namelen)

bool EVP_PKEY_CTX_set_rsa_oaep_label(Crypt::OpenSSL3::PKey::Context ctx, void *label, int len)

bool EVP_PKEY_CTX_get_rsa_oaep_label(Crypt::OpenSSL3::PKey::Context ctx, OUT unsigned char *label)


bool EVP_PKEY_CTX_set_dsa_paramgen_bits(Crypt::OpenSSL3::PKey::Context ctx, int nbits)

bool EVP_PKEY_CTX_set_dsa_paramgen_q_bits(Crypt::OpenSSL3::PKey::Context ctx, int qbits)

bool EVP_PKEY_CTX_set_dsa_paramgen_md(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::MD md)

bool EVP_PKEY_CTX_set_dsa_paramgen_md_props(Crypt::OpenSSL3::PKey::Context ctx, const char *md_name, const char *md_properties)

bool EVP_PKEY_CTX_set_dsa_paramgen_type(Crypt::OpenSSL3::PKey::Context ctx, const char *name)

bool EVP_PKEY_CTX_set_dsa_paramgen_gindex(Crypt::OpenSSL3::PKey::Context ctx, int gindex)

bool EVP_PKEY_CTX_set_dsa_paramgen_seed(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *seed, size_t seedlen)


bool EVP_PKEY_CTX_set_dh_paramgen_prime_len(Crypt::OpenSSL3::PKey::Context ctx, int len)

bool EVP_PKEY_CTX_set_dh_paramgen_subprime_len(Crypt::OpenSSL3::PKey::Context ctx, int len)

bool EVP_PKEY_CTX_set_dh_paramgen_generator(Crypt::OpenSSL3::PKey::Context ctx, int gen)

bool EVP_PKEY_CTX_set_dh_paramgen_type(Crypt::OpenSSL3::PKey::Context ctx, int type)

bool EVP_PKEY_CTX_set_dh_pad(Crypt::OpenSSL3::PKey::Context ctx, int pad)

bool EVP_PKEY_CTX_set_dh_nid(Crypt::OpenSSL3::PKey::Context ctx, int nid)

bool EVP_PKEY_CTX_set_dh_rfc5114(Crypt::OpenSSL3::PKey::Context ctx, int rfc5114)

bool EVP_PKEY_CTX_set_dhx_rfc5114(Crypt::OpenSSL3::PKey::Context ctx, int rfc5114)

bool EVP_PKEY_CTX_set_dh_paramgen_gindex(Crypt::OpenSSL3::PKey::Context ctx, int gindex)

bool EVP_PKEY_CTX_set_dh_paramgen_seed(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *seed, size_t seedlen)

bool EVP_PKEY_CTX_set_dh_kdf_type(Crypt::OpenSSL3::PKey::Context ctx, int kdf)

bool EVP_PKEY_CTX_get_dh_kdf_type(Crypt::OpenSSL3::PKey::Context ctx)

bool EVP_PKEY_CTX_set_dh_kdf_oid(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::ASN1::Object oid)

bool EVP_PKEY_CTX_get_dh_kdf_oid(Crypt::OpenSSL3::PKey::Context ctx, OUT Crypt::OpenSSL3::ASN1::Object oid)

bool EVP_PKEY_CTX_set_dh_kdf_md(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::MD md)

bool EVP_PKEY_CTX_get_dh_kdf_md(Crypt::OpenSSL3::PKey::Context ctx, OUT Crypt::OpenSSL3::MD md)
C_ARGS: ctx, (const EVP_MD**)&md

bool EVP_PKEY_CTX_set_dh_kdf_outlen(Crypt::OpenSSL3::PKey::Context ctx, int len)

bool EVP_PKEY_CTX_get_dh_kdf_outlen(Crypt::OpenSSL3::PKey::Context ctx, OUT int len)


bool EVP_PKEY_CTX_set_ec_paramgen_curve_nid(Crypt::OpenSSL3::PKey::Context ctx, int nid)

bool EVP_PKEY_CTX_set_ec_param_enc(Crypt::OpenSSL3::PKey::Context ctx, int param_enc)

bool EVP_PKEY_CTX_set_ecdh_cofactor_mode(Crypt::OpenSSL3::PKey::Context ctx, int cofactor_mode)

bool EVP_PKEY_CTX_get_ecdh_cofactor_mode(Crypt::OpenSSL3::PKey::Context ctx)

bool EVP_PKEY_CTX_set_ecdh_kdf_type(Crypt::OpenSSL3::PKey::Context ctx, int kdf)

bool EVP_PKEY_CTX_get_ecdh_kdf_type(Crypt::OpenSSL3::PKey::Context ctx)

bool EVP_PKEY_CTX_set_ecdh_kdf_md(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::MD md)

bool EVP_PKEY_CTX_get_ecdh_kdf_md(Crypt::OpenSSL3::PKey::Context ctx, OUT Crypt::OpenSSL3::MD md)
C_ARGS: ctx, (const EVP_MD**)&md

bool EVP_PKEY_CTX_set_ecdh_kdf_outlen(Crypt::OpenSSL3::PKey::Context ctx, int len)

bool EVP_PKEY_CTX_get_ecdh_kdf_outlen(Crypt::OpenSSL3::PKey::Context ctx, OUT int len)

bool EVP_PKEY_CTX_set_id(Crypt::OpenSSL3::PKey::Context ctx, const char* id, size_t length(id))

bool EVP_PKEY_CTX_get_id(Crypt::OpenSSL3::PKey::Context ctx, SV* id)
CODE:
	size_t length;
	EVP_PKEY_CTX_get1_id_len(ctx, &length);
	char* ptr = grow_buffer(id, length);
	RETVAL = EVP_PKEY_CTX_get1_id(ctx, ptr);
	if (RETVAL)
		set_buffer_length(id, length);
OUTPUT:
	RETVAL

bool EVP_PKEY_CTX_set_hkdf_mode(Crypt::OpenSSL3::PKey::Context pctx, int mode)

bool EVP_PKEY_CTX_set_hkdf_md(Crypt::OpenSSL3::PKey::Context pctx, Crypt::OpenSSL3::MD md)

bool EVP_PKEY_CTX_set_hkdf_salt(Crypt::OpenSSL3::PKey::Context pctx, unsigned char *salt, int saltlen)

bool EVP_PKEY_CTX_set_hkdf_key(Crypt::OpenSSL3::PKey::Context pctx, unsigned char *key, int keylen)

bool EVP_PKEY_CTX_add_hkdf_info(Crypt::OpenSSL3::PKey::Context pctx, unsigned char *info, int infolen)

bool EVP_PKEY_CTX_set_signature(Crypt::OpenSSL3::PKey::Context pctx, const unsigned char *sig, size_t siglen)

int EVP_PKEY_CTX_get_keygen_info(Crypt::OpenSSL3::PKey::Context ctx, int idx)


MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3::PKey::Context	PREFIX = EVP_PKEY_

bool EVP_PKEY_keygen_init(Crypt::OpenSSL3::PKey::Context ctx)

bool EVP_PKEY_paramgen_init(Crypt::OpenSSL3::PKey::Context ctx)

NO_OUTPUT bool EVP_PKEY_generate(Crypt::OpenSSL3::PKey::Context ctx, OUTLIST Crypt::OpenSSL3::PKey ppkey)
INIT:
	ppkey = NULL;
POSTCALL:
	if (RETVAL <= 0)
		XSRETURN_UNDEF;

bool EVP_PKEY_parameters_eq(Crypt::OpenSSL3::PKey a, Crypt::OpenSSL3::PKey b)

bool EVP_PKEY_eq(Crypt::OpenSSL3::PKey a, Crypt::OpenSSL3::PKey b)

bool EVP_PKEY_encapsulate_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

bool EVP_PKEY_auth_encapsulate_init(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::PKey authpriv, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, authpriv, params

void EVP_PKEY_encapsulate(Crypt::OpenSSL3::PKey::Context ctx, OUTLIST SV* wrapped_key, OUTLIST SV* gen_key)
CODE:
	size_t wrapped_length, gen_length;
	if (!EVP_PKEY_encapsulate(ctx, NULL, &wrapped_length, NULL, &gen_length))
		XSRETURN_EMPTY;

	char* wrapped_ptr = make_buffer(&wrapped_key, wrapped_length);
	char* gen_ptr = make_buffer(&gen_key, gen_length);

	if (EVP_PKEY_encapsulate(ctx, wrapped_ptr, &wrapped_length, gen_ptr, &gen_length)) {
		set_buffer_length(wrapped_key, wrapped_length);
		set_buffer_length(gen_key, gen_length);
	} else
		XSRETURN_EMPTY;

bool EVP_PKEY_decapsulate_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

bool EVP_PKEY_auth_decapsulate_init(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::PKey authpub, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, authpub, params

SV* EVP_PKEY_decapsulate(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *wrapped, size_t length(wrapped))
CODE:
	size_t unwrapped_length;
	int result = EVP_PKEY_decapsulate(ctx, NULL, &unwrapped_length, wrapped, STRLEN_length_of_wrapped);
	RETVAL = &PL_sv_undef;
	if (result) {
		char* unwrapped_ptr = make_buffer(&RETVAL, unwrapped_length);

		if (EVP_PKEY_decapsulate(ctx, unwrapped_ptr, &unwrapped_length, wrapped, STRLEN_length_of_wrapped))
			set_buffer_length(RETVAL, unwrapped_length);
	}
OUTPUT:
	RETVAL

bool EVP_PKEY_encrypt_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

SV* EVP_PKEY_encrypt(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *in, size_t length(in))
CODE:
	size_t out_length;
	bool result = EVP_PKEY_encrypt(ctx, NULL, &out_length, in, STRLEN_length_of_in);
	RETVAL = &PL_sv_undef;
	if (result) {
		char* out_ptr = make_buffer(&RETVAL, out_length);

		result = EVP_PKEY_encrypt(ctx, out_ptr, &out_length, in, STRLEN_length_of_in);
		if (result)
			set_buffer_length(RETVAL, out_length);
	}
OUTPUT:
	RETVAL

bool EVP_PKEY_decrypt_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

SV* EVP_PKEY_decrypt(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *in, size_t length(in))
CODE:
	size_t out_length;
	bool result = EVP_PKEY_decrypt(ctx, NULL, &out_length, in, STRLEN_length_of_in);
	RETVAL = &PL_sv_undef;
	if (result) {
		char* out_ptr = make_buffer(&RETVAL, out_length);

		result = EVP_PKEY_decrypt(ctx, out_ptr, &out_length, in, STRLEN_length_of_in);
		if (result)
			set_buffer_length(RETVAL, out_length);
	}
OUTPUT:
	RETVAL

bool EVP_PKEY_derive_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, params

bool EVP_PKEY_derive_set_peer(Crypt::OpenSSL3::PKey::Context ctx, Crypt::OpenSSL3::PKey peer, bool validate_peer = false)

SV* EVP_PKEY_derive(Crypt::OpenSSL3::PKey::Context ctx)
CODE:
	size_t key_length;
	bool result = EVP_PKEY_derive(ctx, NULL, &key_length);
	RETVAL = &PL_sv_undef;
	if (result) {
		char* key_ptr = make_buffer(&RETVAL, key_length);

		result = EVP_PKEY_derive(ctx, key_ptr, &key_length);
		if (result)
			set_buffer_length(RETVAL, key_length);
	}
OUTPUT:
	RETVAL

bool EVP_PKEY_sign_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef, Crypt::OpenSSL3::Signature algo = NULL)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, algo, params

bool EVP_PKEY_sign_message_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef, Crypt::OpenSSL3::Signature algo = NULL)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, algo, params

bool EVP_PKEY_sign_message_update(Crypt::OpenSSL3::PKey::Context ctx, unsigned char *in, size_t length(in))

SV* EVP_PKEY_sign_message_final(Crypt::OpenSSL3::PKey::Context ctx)
CODE:
	size_t sigsize;
	bool result = EVP_PKEY_sign_message_final(ctx, NULL, &sigsize);
	RETVAL = &PL_sv_undef;
	if (result) {
		char* ptr = make_buffer(&RETVAL, sigsize);
		result = EVP_PKEY_sign_message_final(ctx, ptr, &sigsize);
		if (result)
			set_buffer_length(RETVAL, sigsize);
	}
OUTPUT:
	RETVAL

SV* EVP_PKEY_sign(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *tbs, size_t length(tbs))
CODE:
	size_t sig_length;
	bool result = EVP_PKEY_sign(ctx, NULL, &sig_length, tbs, STRLEN_length_of_tbs);
	RETVAL = &PL_sv_undef;
	if (result) {
		char* sig_ptr = make_buffer(&RETVAL, sig_length);

		result = EVP_PKEY_sign(ctx, sig_ptr, &sig_length, tbs, STRLEN_length_of_tbs);
		if (result)
			set_buffer_length(RETVAL, sig_length);
	}
OUTPUT:
	RETVAL

bool EVP_PKEY_verify_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef, Crypt::OpenSSL3::Signature algo = NULL)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, algo, params

bool EVP_PKEY_verify_message_init(Crypt::OpenSSL3::PKey::Context ctx, SV* args = undef, Crypt::OpenSSL3::Signature algo = NULL)
INIT:
	const OSSL_PARAM* params = params_for(EVP_PKEY_CTX_settable_params(ctx), args);
C_ARGS: ctx, algo, params

bool EVP_PKEY_verify_message_update(Crypt::OpenSSL3::PKey::Context ctx, unsigned char *in, size_t length(in))

bool EVP_PKEY_verify_message_final(Crypt::OpenSSL3::PKey::Context ctx)

bool EVP_PKEY_verify(Crypt::OpenSSL3::PKey::Context ctx, const unsigned char *sig, size_t length(sig), const unsigned char *tbs, size_t length(tbs))
