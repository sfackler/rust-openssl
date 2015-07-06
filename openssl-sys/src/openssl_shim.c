#include <openssl/hmac.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x1000000L
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

void BIO_set_mem_eof_return_shim(BIO *b, int v) {
    BIO_set_mem_eof_return(b, v);
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

long SSL_CTX_add_extra_chain_cert_shim(SSL_CTX *ctx, X509 *x509) {
    return SSL_CTX_add_extra_chain_cert(ctx, x509);
}

long SSL_CTX_set_read_ahead_shim(SSL_CTX *ctx, long m) {
    return SSL_CTX_set_read_ahead(ctx, m);
}

long SSL_set_tlsext_host_name_shim(SSL *s, char *name) {
    return SSL_set_tlsext_host_name(s, name);
}
