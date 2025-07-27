#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/ssl.h>

#define DUPLICATING_TYPE(c_prefix, xs_type)\
typedef c_prefix *xs_type;\
static int c_prefix ## _magic_dup(pTHX_ MAGIC* mg, CLONE_PARAMS* params) {\
	mg->mg_ptr = (char*)c_prefix ## _dup((xs_type)mg->mg_ptr);\
	return 0;\
}\
static int c_prefix ## _magic_free(pTHX_ SV* sv, MAGIC* mg) {\
	c_prefix ## _free((xs_type)mg->mg_ptr);\
	return 0;\
}\
static const MGVTBL xs_type ## _magic = {\
	.svt_dup = c_prefix ## _magic_dup,\
	.svt_free = c_prefix ## _magic_free,\
};

#define COUNTING_TYPE(c_prefix, xs_type)\
typedef c_prefix *xs_type;\
static int c_prefix ## _magic_dup(pTHX_ MAGIC* mg, CLONE_PARAMS* params) {\
	c_prefix ## _up_ref((xs_type)mg->mg_ptr);\
	return 0;\
}\
static int c_prefix ## _magic_free(pTHX_ SV* sv, MAGIC* mg) {\
	c_prefix ## _free((xs_type)mg->mg_ptr);\
	return 0;\
}\
static const MGVTBL xs_type ## _magic = {\
	.svt_dup = c_prefix ## _magic_dup,\
	.svt_free = c_prefix ## _magic_free,\
};

#define CONSTPTR_TYPE(c_prefix, xs_type)\
typedef const c_prefix *xs_type;\
static const MGVTBL xs_type ## _magic = { NULL };

COUNTING_TYPE(EVP_CIPHER, Crypt__OpenSSL3__Cipher)
DUPLICATING_TYPE(EVP_CIPHER_CTX, Crypt__OpenSSL3__Cipher__Context)
COUNTING_TYPE(EVP_MD, Crypt__OpenSSL3__MD)
DUPLICATING_TYPE(EVP_MD_CTX, Crypt__OpenSSL3__MD__Context)
COUNTING_TYPE(EVP_PKEY, Crypt__OpenSSL3__PrivateKey)

COUNTING_TYPE(X509, Crypt__OpenSSL3__X509)
COUNTING_TYPE(X509_STORE, Crypt__OpenSSL3__X509__Store)
DUPLICATING_TYPE(X509_NAME, Crypt__OpenSSL3__X509__Name)
DUPLICATING_TYPE(X509_NAME_ENTRY, Crypt__OpenSSL3__X509__Name__Entry)

COUNTING_TYPE(BIO, Crypt__OpenSSL3__BIO)

CONSTPTR_TYPE(SSL_METHOD, Crypt__OpenSSL3__SSL__Protocol)
COUNTING_TYPE(SSL_CTX, Crypt__OpenSSL3__SSL__Context)
COUNTING_TYPE(SSL, Crypt__OpenSSL3__SSL)
COUNTING_TYPE(SSL_SESSION, Crypt__OpenSSL3__SSL__Session)

SV* S_make_object(pTHX_ void* var, const MGVTBL* mgvtbl, const char* ntype) {
	SV* result = newSV(0);
	MAGIC* magic = sv_magicext(newSVrv(result, ntype), NULL, PERL_MAGIC_ext, mgvtbl, (const char*)var, 0);
	magic->mg_flags |= MGf_DUP;
	return result;
}
#define make_object(var, magic, name) S_make_object(aTHX_ var, magic, name)

#define BIO_new_mem(class) BIO_new(BIO_s_mem())

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

#define CONSTANT2(PREFIX, VALUE) newCONSTSUB(stash, #VALUE, newSVuv(PREFIX##VALUE))

char* S_grow_buffer(pTHX_ SV* buffer, size_t size) {
	SvUPGRADE(buffer, SVt_PV);
	SV_CHECK_THINKFIRST(buffer);
	SvPOK_only(buffer);
	return SvGROW(buffer, size);
}
#define grow_buffer(sv, size) S_grow_buffer(aTHX_ sv, size)

#define set_buffer_length(buffer, result) STMT_START { if (result >= 0) SvCUR_set(buffer, result); } STMT_END

// This will force byte semantics on all strings
#undef SvPV
#define SvPV(sv, len) SvPVbyte(sv, len)
#undef SvPV_nolen
#define SvPV_nolen(sv) SvPVbyte_nolen(sv)

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

void EVP_CIPHER_provided_callback(EVP_CIPHER* provided, void* vdata) {
	struct EVP_callback_data* data = vdata;
	dTHXa(data->interpreter);
	EVP_CIPHER_up_ref(provided);
	SV* object = make_object(provided, &Crypt__OpenSSL3__Cipher_magic, "Crypt::OpenSSL3::Cipher");
	call_callback(data->sv, object);
}

void EVP_MD_provided_callback(EVP_MD* provided, void* vdata) {
	struct EVP_callback_data* data = vdata;
	dTHXa(data->interpreter);
	EVP_MD_up_ref(provided);
	SV* object = make_object(provided, &Crypt__OpenSSL3__MD_magic, "Crypt::OpenSSL3::MD");
	call_callback(data->sv, object);
}

MODULE = Crypt::OpenSSL3	PACKAGE = Crypt::OpenSSL3

TYPEMAP: <<END
const unsigned char*	T_PV

Crypt::OpenSSL3::Cipher T_MAGICEXT
Crypt::OpenSSL3::Cipher::Context T_MAGICEXT
Crypt::OpenSSL3::MD T_MAGICEXT
Crypt::OpenSSL3::MD::Context T_MAGICEXT
Crypt::OpenSSL3::PrivateKey T_MAGICEXT

Crypt::OpenSSL3::BIO T_MAGICEXT

Crypt::OpenSSL3::X509	T_MAGICEXT
Crypt::OpenSSL3::X509::Store	T_MAGICEXT
Crypt::OpenSSL3::X509::Name	T_MAGICEXT
Crypt::OpenSSL3::X509::Name::Entry	T_MAGICEXT

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

int EVP_CIPHER_names_do_all(Crypt::OpenSSL3::Cipher cipher, SV* callback)
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

bool init(Crypt::OpenSSL3::Cipher::Context ctx, Crypt::OpenSSL3::Cipher cipher, const unsigned char* key, const unsigned char* iv, int enc)
CODE:
	OSSL_PARAM params[1] = { OSSL_PARAM_construct_end() };
	RETVAL = EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, params);
OUTPUT:
	RETVAL

bool update(Crypt::OpenSSL3::Cipher::Context ctx, SV* output, const char* input, size_t length(input))
CODE:
	char* ptr = grow_buffer(output, STRLEN_length_of_input);
	int outl = STRLEN_length_of_input;
	RETVAL = EVP_CipherUpdate(ctx, ptr, &outl, input, STRLEN_length_of_input);
	set_buffer_length(output, outl);
OUTPUT:
	RETVAL

bool final(Crypt::OpenSSL3::Cipher::Context ctx, SV* output, int size = -1)
CODE:
	if (size == -1)
		size = EVP_CIPHER_CTX_get_block_size(ctx);
	char* ptr = grow_buffer(output, size);
	RETVAL = EVP_CipherFinal_ex(ctx, ptr, &size);
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

int EVP_MD_names_do_all(Crypt::OpenSSL3::MD md, SV* callback)
INIT:
	struct EVP_callback_data data;
#ifdef MULTIPLICITY
	data.interpreter = aTHX;
#endif
	data.sv = callback;
C_ARGS:
	md, EVP_name_callback, &data

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

bool EVP_MD_CTX_init(Crypt::OpenSSL3::MD::Context ctx, Crypt::OpenSSL3::MD type)
INIT:
	OSSL_PARAM params[1] = { OSSL_PARAM_construct_end() };
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
	set_buffer_length(buffer, size);

bool EVP_MD_CTX_final_xof(Crypt::OpenSSL3::MD::Context ctx, SV* buffer, size_t outlen)
INIT:
	char* ptr = grow_buffer(buffer, outlen);
C_ARGS:
	ctx, ptr, outlen
POSTCALL:
	set_buffer_length(buffer, outlen);

bool EVP_MD_CTX_squeeze(Crypt::OpenSSL3::MD::Context ctx, SV* buffer, size_t outlen)
INIT:
	char* ptr = grow_buffer(buffer, outlen);
C_ARGS:
	ctx, ptr, outlen
POSTCALL:
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
