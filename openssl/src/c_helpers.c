#include <openssl/ssl.h>

void rust_SSL_clone(SSL *ssl) {
    CRYPTO_add(&ssl->references, 1, CRYPTO_LOCK_SSL);
}

void rust_SSL_CTX_clone(SSL_CTX *ctx) {
    CRYPTO_add(&ctx->references,1,CRYPTO_LOCK_SSL_CTX);
}

void rust_X509_clone(X509 *x509) {
    CRYPTO_add(&x509->references,1,CRYPTO_LOCK_X509);
}
