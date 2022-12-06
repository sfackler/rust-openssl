#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include "testutil.h"
#include "../ssl/ssl_local.h"

#ifndef OPENSSL_NO_NTLS

static const char *sm2_sign_cert_file;
static const char *sm2_sign_key_file;
static const char *sm2_enc_cert_file;
static const char *sm2_enc_key_file;
static const char *rsa_sign_cert_file;
static const char *rsa_sign_key_file;
static const char *rsa_enc_cert_file;
static const char *rsa_enc_key_file;

static const char *cipher_list[] = {
# ifndef OPENSSL_NO_SM4
#  ifndef OPENSSL_NO_SM3
#   ifndef OPENSSL_NO_SM2
    NTLS_TXT_SM2DHE_WITH_SM4_SM3,
    NTLS_TXT_SM2_WITH_SM4_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_GCM_SM3,
    NTLS_TXT_ECC_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECC_SM2_SM4_GCM_SM3,
    NTLS_TXT_SM2DHE_WITH_SM4_SM3":"NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3":"NTLS_TXT_ECDHE_SM2_SM4_GCM_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3":"NTLS_TXT_ECC_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3":"NTLS_TXT_RSA_SM4_CBC_SM3,
#   endif /* OPENSSL_NO_SM2 */
    NTLS_TXT_RSA_SM4_CBC_SM3,
    NTLS_TXT_RSA_SM4_GCM_SM3,
#  endif /* OPENSSL_NO_SM3 */
    NTLS_TXT_RSA_SM4_CBC_SHA256,
    NTLS_TXT_RSA_SM4_GCM_SHA256,
# endif /* OPENSSL_NO_SM4 */
    NULL,   /* suppress compile error: zero or negative size array */
};

static int test_ntls_ctx_set_cipher_list(int i)
{
    int           ret = 1;
#ifndef OPENSSL_NO_NTLS
    SSL_CTX      *ctx = NULL;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_client_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    SSL_CTX_enable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 1))
        goto err;

    if (!TEST_true(SSL_CTX_set_cipher_list(ctx, cipher_list[i]))) {
        goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
#endif
    return ret;
}

static int test_ntls_ssl_set_cipher_list(int i)
{
    int           ret = 1;
#ifndef OPENSSL_NO_NTLS
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_client_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    SSL_CTX_enable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 1))
        goto err;


    ssl = SSL_new(ctx);
    if (!TEST_true(ssl != NULL))
        goto err;

    if (!TEST_true(SSL_CTX_set_cipher_list(ctx, cipher_list[i]))) {
        goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
    SSL_free(ssl);
#endif
    return ret;
}

static int test_ntls_ctx_set_cert_pkey_file_api(int i)
{
    int ret = 1;
#ifndef OPENSSL_NO_NTLS
    const char *sign_cert_file = NULL;
    const char *sign_key_file = NULL;
    const char *enc_cert_file = NULL;
    const char *enc_key_file = NULL;
    SSL_CTX *ctx = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    SSL_CTX_enable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 1))
        goto err;
    SSL_CTX_disable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 0))
        goto err;

    if (!TEST_int_eq(SSL_CTX_use_sign_certificate_file(ctx,
                                                       sign_cert_file,
                                                       SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_sign_PrivateKey_file(ctx,
                                                      sign_key_file,
                                                      SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_certificate_file(ctx,
                                                      enc_cert_file,
                                                      SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_PrivateKey_file(ctx,
                                                     enc_key_file,
                                                     SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
#endif
    return ret;
}

static int test_ntls_ssl_set_cert_pkey_file_api(int i)
{
    int           ret = 1;
#ifndef OPENSSL_NO_NTLS
    const char   *sign_cert_file = NULL;
    const char   *sign_key_file = NULL;
    const char   *enc_cert_file = NULL;
    const char   *enc_key_file = NULL;
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    ssl = SSL_new(ctx);
    if (!TEST_true(ssl != NULL))
        goto err;

    if (!TEST_true(SSL_is_ntls(ssl) == 1))
        goto err;

    SSL_enable_ntls(ssl);
    if (!TEST_true(ssl->enable_ntls == 1))
        goto err;
    SSL_disable_ntls(ssl);
    if (!TEST_true(ssl->enable_ntls == 0))
        goto err;

    if (!TEST_int_eq(SSL_use_sign_certificate_file(ssl,
                                                   sign_cert_file,
                                                   SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_sign_PrivateKey_file(ssl,
                                                  sign_key_file,
                                                  SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_certificate_file(ssl,
                                                  enc_cert_file,
                                                  SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_PrivateKey_file(ssl,
                                                 enc_key_file,
                                                 SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
    SSL_free(ssl);
#endif
    return ret;
}

static int test_ntls_ctx_set_cert_pkey_api(int i)
{
    int           ret = 1;
#ifndef OPENSSL_NO_NTLS
    SSL_CTX      *ctx = NULL;
    X509         *sign_cert = NULL;
    EVP_PKEY     *sign_pkey = NULL;
    X509         *enc_cert = NULL;
    EVP_PKEY     *enc_pkey = NULL;
    BIO          *sign_cert_bio = NULL;
    BIO          *sign_pkey_bio = NULL;
    BIO          *enc_cert_bio = NULL;
    BIO          *enc_pkey_bio = NULL;
    const char   *sign_cert_file = NULL;
    const char   *sign_key_file = NULL;
    const char   *enc_cert_file = NULL;
    const char   *enc_key_file = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    sign_cert_bio = BIO_new(BIO_s_file());
    enc_cert_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_cert_bio) || !TEST_ptr(enc_cert_bio))
        goto err;

    if (!TEST_int_eq(BIO_read_filename(sign_cert_bio, sign_cert_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_cert_bio, enc_cert_file), 1))
        goto err;

    sign_cert = PEM_read_bio_X509(sign_cert_bio, NULL, NULL, NULL);
    enc_cert = PEM_read_bio_X509(enc_cert_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_cert) || !TEST_ptr(enc_cert))
        goto err;

    sign_pkey_bio = BIO_new(BIO_s_file());
    enc_pkey_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_pkey_bio) || !TEST_ptr(enc_pkey_bio))
        goto err;

    if (!TEST_int_eq(BIO_read_filename(sign_pkey_bio, sign_key_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_pkey_bio, enc_key_file), 1))
        goto err;

    sign_pkey = PEM_read_bio_PrivateKey(sign_pkey_bio, NULL, NULL, NULL);
    enc_pkey = PEM_read_bio_PrivateKey(enc_pkey_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_pkey) || !TEST_ptr(enc_pkey))
        goto err;


    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;


    if (!TEST_int_eq(SSL_CTX_use_sign_certificate(ctx, sign_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_sign_PrivateKey(ctx, sign_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_certificate(ctx, enc_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_PrivateKey(ctx, enc_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    BIO_free(sign_cert_bio);
    BIO_free(enc_cert_bio);
    BIO_free(sign_pkey_bio);
    BIO_free(enc_pkey_bio);
    X509_free(sign_cert);
    X509_free(enc_cert);
    EVP_PKEY_free(sign_pkey);
    EVP_PKEY_free(enc_pkey);
    SSL_CTX_free(ctx);
#endif
    return ret;
}

static int test_ntls_ssl_set_cert_pkey_api(int i)
{
    int           ret = 1;
#ifndef OPENSSL_NO_NTLS
    const char   *sign_cert_file = NULL;
    const char   *sign_key_file = NULL;
    const char   *enc_cert_file = NULL;
    const char   *enc_key_file = NULL;
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;
    X509         *sign_cert = NULL;
    EVP_PKEY     *sign_pkey = NULL;
    X509         *enc_cert = NULL;
    EVP_PKEY     *enc_pkey = NULL;
    BIO          *sign_cert_bio = NULL;
    BIO          *sign_pkey_bio = NULL;
    BIO          *enc_cert_bio = NULL;
    BIO          *enc_pkey_bio = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    sign_cert_bio = BIO_new(BIO_s_file());
    enc_cert_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_cert_bio) || !TEST_ptr(enc_cert_bio))
        goto err;
    if (!TEST_int_eq(BIO_read_filename(sign_cert_bio, sign_cert_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_cert_bio, enc_cert_file), 1))
        goto err;
    sign_cert = PEM_read_bio_X509(sign_cert_bio, NULL, NULL, NULL);
    enc_cert = PEM_read_bio_X509(enc_cert_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_cert) || !TEST_ptr(enc_cert))
        goto err;

    sign_pkey_bio = BIO_new(BIO_s_file());
    enc_pkey_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_pkey_bio) || !TEST_ptr(enc_pkey_bio))
        goto err;
    if (!TEST_int_eq(BIO_read_filename(sign_pkey_bio, sign_key_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_pkey_bio, enc_key_file), 1))
        goto err;
    sign_pkey = PEM_read_bio_PrivateKey(sign_pkey_bio, NULL, NULL, NULL);
    enc_pkey = PEM_read_bio_PrivateKey(enc_pkey_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_pkey) || !TEST_ptr(enc_pkey))
        goto err;

    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;
    ssl = SSL_new(ctx);
    if (!TEST_true(ssl != NULL))
        goto err;

    if (!TEST_int_eq(SSL_use_sign_certificate(ssl, sign_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_sign_PrivateKey(ssl, sign_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_certificate(ssl, enc_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_PrivateKey(ssl, enc_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ssl->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    BIO_free(sign_cert_bio);
    BIO_free(enc_cert_bio);
    BIO_free(sign_pkey_bio);
    BIO_free(enc_pkey_bio);
    X509_free(sign_cert);
    X509_free(enc_cert);
    EVP_PKEY_free(sign_pkey);
    EVP_PKEY_free(enc_pkey);
    SSL_CTX_free(ctx);
    SSL_free(ssl);
#endif
    return ret;
}

static int test_ntls_method_api(void)
{
    int ret = 1;
#ifndef OPENSSL_NO_NTLS
    const SSL_METHOD *meth = NULL;

    ret = 0;
    meth = NTLS_method();
    if (!TEST_true(meth->version == NTLS_VERSION))
        goto err;
    if (!TEST_true(meth->flags == SSL_METHOD_NO_SUITEB))
        goto err;
    if (!TEST_true(meth->mask == SSL_OP_NO_NTLS))
        goto err;

    meth = NTLS_server_method();
    if (!TEST_true(meth->version == NTLS_VERSION))
        goto err;
    if (!TEST_true(meth->flags == SSL_METHOD_NO_SUITEB))
        goto err;
    if (!TEST_true(meth->mask == SSL_OP_NO_NTLS))
        goto err;

    meth = NTLS_client_method();
    if (!TEST_true(meth->version == NTLS_VERSION))
        goto err;
    if (!TEST_true(meth->flags == SSL_METHOD_NO_SUITEB))
        goto err;
    if (!TEST_true(meth->mask == SSL_OP_NO_NTLS))
        goto err;

    ret = 1;
err:
#endif
    return ret;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_NTLS
    if (!TEST_ptr(sm2_sign_cert_file = test_get_argument(0))
            || !TEST_ptr(sm2_sign_key_file = test_get_argument(1))
            || !TEST_ptr(sm2_enc_cert_file = test_get_argument(2))
            || !TEST_ptr(sm2_enc_key_file = test_get_argument(3))
            || !TEST_ptr(rsa_sign_cert_file = test_get_argument(4))
            || !TEST_ptr(rsa_sign_key_file = test_get_argument(5))
            || !TEST_ptr(rsa_enc_cert_file = test_get_argument(6))
            || !TEST_ptr(rsa_enc_key_file = test_get_argument(7))) {
        TEST_note("usage: ssl_ntls_api_test cert.pem|key.pem");
        return 0;
    }
    ADD_ALL_TESTS(test_ntls_ctx_set_cert_pkey_file_api, 2);
    ADD_ALL_TESTS(test_ntls_ctx_set_cert_pkey_api, 2);
    ADD_ALL_TESTS(test_ntls_ssl_set_cert_pkey_file_api, 2);
    ADD_ALL_TESTS(test_ntls_ssl_set_cert_pkey_api, 2);
    ADD_TEST(test_ntls_method_api);

    ADD_ALL_TESTS(test_ntls_ctx_set_cipher_list, OSSL_NELEM(cipher_list) - 1);
    ADD_ALL_TESTS(test_ntls_ssl_set_cipher_list, OSSL_NELEM(cipher_list) - 1);
#endif
    return 1;
}
