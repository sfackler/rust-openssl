#include <openssl/ssl.h>

void rust_SSL_clone(SSL *ssl) {
    CRYPTO_add(&ssl->references, 1, CRYPTO_LOCK_SSL);
}

void rust_SSL_CTX_clone(SSL_CTX *ctx) {
    CRYPTO_add(&ctx->references,1,CRYPTO_LOCK_SSL_CTX);
}
