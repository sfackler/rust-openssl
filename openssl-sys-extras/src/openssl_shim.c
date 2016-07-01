#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#if OPENSSL_VERSION_NUMBER < 0x10000000L
// Copied from openssl crypto/hmac/hmac.c
int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx)
     {
     if (!EVP_MD_CTX_copy(&dctx->i_ctx, &sctx->i_ctx))
         goto err;
     if (!EVP_MD_CTX_copy(&dctx->o_ctx, &sctx->o_ctx))
         goto err;
     if (!EVP_MD_CTX_copy(&dctx->md_ctx, &sctx->md_ctx))
         goto err;
     memcpy(dctx->key, sctx->key, HMAC_MAX_MD_CBLOCK);
     dctx->key_length = sctx->key_length;
     dctx->md = sctx->md;
     return 1;
     err:
     return 0;
     }

int HMAC_Init_ex_shim(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl) {
    HMAC_Init_ex(ctx, key, key_len, md, impl);
    return 1;
}

int HMAC_Update_shim(HMAC_CTX *ctx, const unsigned char *data, int len) {
    HMAC_Update(ctx, data, len);
    return 1;
}

int HMAC_Final_shim(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) {
    HMAC_Final(ctx, md, len);
    return 1;
}

#else

int HMAC_Init_ex_shim(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl) {
    return HMAC_Init_ex(ctx, key, key_len, md, impl);
}

int HMAC_Update_shim(HMAC_CTX *ctx, const unsigned char *data, int len) {
    return HMAC_Update(ctx, data, len);
}

int HMAC_Final_shim(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) {
    return HMAC_Final(ctx, md, len);
}
#endif

// shims for OpenSSL macros

int BIO_eof_shim(BIO *b) {
    return BIO_eof(b);
}

long BIO_set_nbio_shim(BIO *b, long enabled) {
    return BIO_set_nbio(b, enabled);
}

void BIO_set_mem_eof_return_shim(BIO *b, int v) {
    BIO_set_mem_eof_return(b, v);
}

void BIO_clear_retry_flags_shim(BIO *b) {
    BIO_clear_retry_flags(b);
}

void BIO_set_retry_read_shim(BIO *b) {
    BIO_set_retry_read(b);
}

void BIO_set_retry_write_shim(BIO *b) {
    BIO_set_retry_write(b);
}

long BIO_flush_shim(BIO *b) {
    return BIO_flush(b);
}

long SSL_CTX_set_options_shim(SSL_CTX *ctx, long options) {
    return SSL_CTX_set_options(ctx, options);
}

long SSL_CTX_get_options_shim(SSL_CTX *ctx) {
    return SSL_CTX_get_options(ctx);
}

long SSL_CTX_clear_options_shim(SSL_CTX *ctx, long options) {
    return SSL_CTX_clear_options(ctx, options);
}

long SSL_CTX_set_mode_shim(SSL_CTX *ctx, long options) {
    return SSL_CTX_set_mode(ctx, options);
}

long SSL_CTX_add_extra_chain_cert_shim(SSL_CTX *ctx, X509 *x509) {
    return SSL_CTX_add_extra_chain_cert(ctx, x509);
}

long SSL_CTX_set_read_ahead_shim(SSL_CTX *ctx, long m) {
    return SSL_CTX_set_read_ahead(ctx, m);
}

long SSL_CTX_set_tmp_dh_shim(SSL_CTX *ctx, DH *dh) {
    return SSL_CTX_set_tmp_dh(ctx, dh);
}

long SSL_CTX_set_tlsext_servername_callback_shim(SSL_CTX *ctx, int (*callback)(SSL_CTX *, int *, void*)) {
    return SSL_CTX_set_tlsext_servername_callback(ctx, callback);
}

long SSL_CTX_set_tlsext_servername_arg_shim(SSL_CTX *ctx, void* arg) {
    return SSL_CTX_set_tlsext_servername_arg(ctx, arg);
}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
int SSL_CTX_set_ecdh_auto_shim(SSL_CTX *ctx, int onoff) {
    return SSL_CTX_set_ecdh_auto(ctx, onoff);
}
#endif

DH *DH_new_from_params(BIGNUM *p, BIGNUM *g, BIGNUM *q) {
    DH *dh;

    if ((dh = DH_new()) == NULL) {
        return NULL;
    }
    dh->p = p;
    dh->g = g;
    dh->q = q;
    return dh;
}

long SSL_set_tlsext_host_name_shim(SSL *s, char *name) {
    return SSL_set_tlsext_host_name(s, name);
}

STACK_OF(X509_EXTENSION) *X509_get_extensions_shim(X509 *x) {
    return x->cert_info ? x->cert_info->extensions : NULL;
}
