#include <openssl/ssl.h>

void rust_SSL_clone(SSL *ssl) {
    CRYPTO_add(&ssl->references, 1, CRYPTO_LOCK_SSL);
}
