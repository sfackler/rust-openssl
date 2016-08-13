#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

void rust_0_8_SSL_CTX_clone(SSL_CTX *ctx) {
    CRYPTO_add(&ctx->references,1,CRYPTO_LOCK_SSL_CTX);
}

void rust_0_8_X509_clone(X509 *x509) {
    CRYPTO_add(&x509->references,1,CRYPTO_LOCK_X509);
}

STACK_OF(X509_EXTENSION) *rust_0_8_X509_get_extensions(X509 *x) {
    return x->cert_info ? x->cert_info->extensions : NULL;
}

DH *rust_0_8_DH_new_from_params(BIGNUM *p, BIGNUM *g, BIGNUM *q) {
    DH *dh;

    if ((dh = DH_new()) == NULL) {
        return NULL;
    }
    dh->p = p;
    dh->g = g;
    dh->q = q;
    return dh;
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
int rust_0_8_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl) {
    HMAC_Init_ex(ctx, key, key_len, md, impl);
    return 1;
}

int rust_0_8_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len) {
    HMAC_Update(ctx, data, len);
    return 1;
}

int rust_0_8_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) {
    HMAC_Final(ctx, md, len);
    return 1;
}

#else

int rust_0_8_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl) {
    return HMAC_Init_ex(ctx, key, key_len, md, impl);
}

int rust_0_8_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len) {
    return HMAC_Update(ctx, data, len);
}

int rust_0_8_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) {
    return HMAC_Final(ctx, md, len);
}
#endif
