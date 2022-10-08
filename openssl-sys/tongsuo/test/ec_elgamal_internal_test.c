/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include "internal/nelem.h"
#include "testutil.h"
#include <openssl/conf.h>
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <time.h>
#include "../crypto/ec/ec_elgamal.h"

#define EC_PUB_FILE_PATH    "ec-pub.pem"
#define EC_KEY_FILE_PATH    "ec-key.pem"

static size_t ec_elgamal_encrypt(EC_ELGAMAL_CTX *ctx,
                                 unsigned char **out, int32_t plaintext)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_encrypt(ctx, r, plaintext)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static uint32_t ec_elgamal_decrypt(EC_ELGAMAL_CTX *ctx,
                                   unsigned char *in, size_t size)
{
    int32_t r = 0;
    EC_ELGAMAL_CIPHERTEXT *c = NULL;

    if (!TEST_ptr(c = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c, in, size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_decrypt(ctx, &r, c)))
        goto err;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c);
    return r;
}

static size_t ec_elgamal_add(EC_ELGAMAL_CTX *ctx, unsigned char **out,
                             unsigned char *in1, size_t in1_size,
                             unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c2 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c1, in1, in1_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c2, in2, in2_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_add(ctx, r, c1, c2)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static size_t ec_elgamal_sub(EC_ELGAMAL_CTX *ctx, unsigned char **out,
                             unsigned char *in1, size_t in1_size,
                             unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c2 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c1, in1, in1_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c2, in2, in2_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_sub(ctx, r, c1, c2)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static size_t ec_elgamal_mul(EC_ELGAMAL_CTX *ctx, unsigned char **out,
                             unsigned char *in, size_t in_size, uint32_t m)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c, in, in_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_mul(ctx, r, c, m)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static int ec_elgamal_test(int curve_id)
{
    int ret = 0;
    BIO *bio = NULL;
    EC_KEY *eckey = NULL, *ec_pub_key = NULL, *ec_pri_key = NULL;
    //uint32_t p1 = 2000000021, p2 = 500, m = 800, r;
    int32_t p1 = 111111, p2 = 555555, m = 3, r;
    unsigned char *buf = NULL, *buf1 = NULL, *buf2 = NULL;
    size_t size, size1, size2;
    EC_ELGAMAL_CTX *ectx = NULL, *dctx = NULL;
    EC_ELGAMAL_DECRYPT_TABLE *dtable = NULL;

    TEST_info("Testing encrypt/descrypt of EC-ElGamal for curve_id: %d\n", curve_id);

    if (!TEST_ptr(eckey = EC_KEY_new_by_curve_name(curve_id)))
        goto err;

    if (!TEST_true(EC_KEY_generate_key(eckey)))
        goto err;

    /*
     * saving ec public key to pem file for this test
     */
    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_write_filename(bio, EC_PUB_FILE_PATH))
        || !TEST_true(PEM_write_bio_EC_PUBKEY(bio, eckey)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_read_filename(bio, EC_PUB_FILE_PATH))
        || !TEST_ptr(ec_pub_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL,
                                                         NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(ectx = EC_ELGAMAL_CTX_new(ec_pub_key)))
        goto err;

    /*
     * saving ec secret key to pem file for this test
     */
    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_write_filename(bio, EC_KEY_FILE_PATH))
        || !TEST_true(PEM_write_bio_ECPrivateKey(bio, eckey, NULL, NULL, 0,
                                                 NULL, NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_read_filename(bio, EC_KEY_FILE_PATH))
        || !TEST_true(ec_pri_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL,
                                                             NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(dctx = EC_ELGAMAL_CTX_new(ec_pri_key)))
        goto err;

    if (!TEST_ptr(dtable = EC_ELGAMAL_DECRYPT_TABLE_new(dctx, 1)))
        goto err;

    EC_ELGAMAL_CTX_set_decrypt_table(dctx, dtable);

    size1 = ec_elgamal_encrypt(ectx, &buf1, p1);
    if (!TEST_ptr(buf1))
        goto err;

    r = ec_elgamal_decrypt(dctx, buf1, size1);
    if (!TEST_uint_eq(r, p1))
        goto err;

    size2 = ec_elgamal_encrypt(ectx, &buf2, p2);
    if (!TEST_ptr(buf2))
        goto err;

    size = ec_elgamal_add(ectx, &buf, buf1, size1, buf2, size2);
    if (!TEST_ptr(buf))
        goto err;

    r = ec_elgamal_decrypt(dctx, buf, size);
    if (!TEST_uint_eq(r, p1 + p2))
        goto err;

    OPENSSL_free(buf);
    size = ec_elgamal_sub(ectx, &buf, buf1, size1, buf2, size2);
    if (!TEST_ptr(buf))
        goto err;

    r = ec_elgamal_decrypt(dctx, buf, size);
    if (!TEST_uint_eq(r, p1 - p2))
        goto err;

    OPENSSL_free(buf);
    size = ec_elgamal_mul(ectx, &buf, buf2, size2, m);
    if (!TEST_ptr(buf))
        goto err;

    r = ec_elgamal_decrypt(dctx, buf, size);
    if (!TEST_uint_eq(r, m * p2))
        goto err;

    ret = 1;

err:
    EC_ELGAMAL_DECRYPT_TABLE_free(dtable);

    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    OPENSSL_free(buf);
    EC_KEY_free(eckey);
    EC_KEY_free(ec_pub_key);
    EC_KEY_free(ec_pri_key);

    EC_ELGAMAL_CTX_free(ectx);
    EC_ELGAMAL_CTX_free(dctx);

    return ret;
}

static int ec_elgamal_tests(void)
{
    if (!TEST_true(ec_elgamal_test(NID_X9_62_prime256v1)))
        return 0;

#ifndef OPENSSL_NO_SM2
    if (!TEST_true(ec_elgamal_test(NID_sm2)))
        return 0;
#endif

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(ec_elgamal_tests);
    return 1;
}

void cleanup_tests(void)
{
}
