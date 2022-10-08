/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Tests of the EVP_KDF_CTX APIs */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "testutil.h"

static int test_kdf_tls1_prf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_TLS1_PRF)) == NULL) {
        TEST_error("EVP_KDF_TLS1_PRF");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_TLS_SECRET,
                     "secret", (size_t)6) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_TLS_SECRET");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_TLS_SEED, "seed", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_ADD_TLS_SEED");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x8e, 0x4d, 0x93, 0x25, 0x30, 0xd7, 0x65, 0xa0,
            0xaa, 0xe9, 0x74, 0xc3, 0x04, 0x73, 0x5e, 0xcc
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_hkdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[10];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_HKDF)) == NULL) {
        TEST_error("EVP_KDF_HKDF");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, "secret", (size_t)6) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KEY");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_HKDF_INFO,
                     "label", (size_t)5) <= 0) {
        TEST_error("EVP_KDF_CTRL_ADD_HKDF_INFO");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x2a, 0xc4, 0x36, 0x9f, 0x52, 0x59, 0x96, 0xf8, 0xde, 0x13
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_pbkdf2(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[32];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_PBKDF2)) == NULL) {
        TEST_error("EVP_KDF_PBKDF2");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, "password", (size_t)8) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_PASS");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_ITER, 2) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_ITER");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
            0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
            0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
            0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

#ifndef OPENSSL_NO_SCRYPT
static int test_kdf_scrypt(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[64];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_SCRYPT)) == NULL) {
        TEST_error("EVP_KDF_SCRYPT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, "password", (size_t)8) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_PASS");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "NaCl", (size_t)4) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_N, (uint64_t)1024) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SCRYPT_N");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_R, (uint32_t)8) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SCRYPT_R");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_P, (uint32_t)16) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SCRYPT_P");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES, (uint64_t)16) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MAXMEM_BYTES");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) > 0) {
        TEST_error("EVP_KDF_derive should have failed");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES,
                     (uint64_t)(10 * 1024 * 1024)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MAXMEM_BYTES");
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
            0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
            0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
            0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
            0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
            0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
            0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
        };
        if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}
#endif

/*
 * KBKDF test vectors from RFC 6803 (Camellia Encryption for Kerberos 5)
 * section 10.
 */
#ifndef OPENSSL_NO_CAMELLIA
static int test_kdf_kbkdf_6803_128(void)
{
    int ret = 0, i;
    EVP_KDF_CTX *kctx;
    static unsigned char input_key[] = {
        0x57, 0xD0, 0x29, 0x72, 0x98, 0xFF, 0xD9, 0xD3,
        0x5D, 0xE5, 0xA4, 0x7F, 0xB4, 0xBD, 0xE2, 0x4B,
    };
    static unsigned char constants[][5] = {
        { 0x00, 0x00, 0x00, 0x02, 0x99 },
        { 0x00, 0x00, 0x00, 0x02, 0xaa },
        { 0x00, 0x00, 0x00, 0x02, 0x55 },
    };
    static unsigned char outputs[][16] = {
        {0xD1, 0x55, 0x77, 0x5A, 0x20, 0x9D, 0x05, 0xF0,
         0x2B, 0x38, 0xD4, 0x2A, 0x38, 0x9E, 0x5A, 0x56},
        {0x64, 0xDF, 0x83, 0xF8, 0x5A, 0x53, 0x2F, 0x17,
         0x57, 0x7D, 0x8C, 0x37, 0x03, 0x57, 0x96, 0xAB},
        {0x3E, 0x4F, 0xBD, 0xF3, 0x0F, 0xB8, 0x25, 0x9C,
         0x42, 0x5C, 0xB6, 0xC9, 0x6F, 0x1F, 0x46, 0x35}
    };
    static unsigned char iv[16] = { 0 };
    unsigned char result[16] = { 0 };

    for (i = 0; i < 3; i++) {
        ret = 0;
        if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_KB)) == NULL) {
            TEST_error("EVP_KDF_KB");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MAC_TYPE, EVP_KDF_KB_MAC_TYPE_CMAC) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KB_MAC_TYPE");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MODE, EVP_KDF_KB_MODE_FEEDBACK) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KB_MODE");
            goto err;
        }
	if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_CIPHER, EVP_camellia_128_cbc()) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_CIPHER");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, input_key, sizeof(input_key)) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KEY");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, constants[i], sizeof(constants[i])) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_SALT");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_SEED, iv, sizeof(iv)) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KB_SEED");
            goto err;
        }
        ret = TEST_int_gt(EVP_KDF_derive(kctx, result, sizeof(result)), 0)
            && TEST_mem_eq(result, sizeof(result), outputs[i],
                           sizeof(outputs[i]));
err:
        EVP_KDF_CTX_free(kctx);
        if (ret != 1)
            return ret;
    }
    return ret;
}
#endif

#ifndef OPENSSL_NO_CAMELLIA
static int test_kdf_kbkdf_6803_256(void)
{
    int ret = 0, i;
    EVP_KDF_CTX *kctx;
    static unsigned char input_key[] = {
        0xB9, 0xD6, 0x82, 0x8B, 0x20, 0x56, 0xB7, 0xBE,
        0x65, 0x6D, 0x88, 0xA1, 0x23, 0xB1, 0xFA, 0xC6,
        0x82, 0x14, 0xAC, 0x2B, 0x72, 0x7E, 0xCF, 0x5F,
        0x69, 0xAF, 0xE0, 0xC4, 0xDF, 0x2A, 0x6D, 0x2C,
    };
    static unsigned char constants[][5] = {
        { 0x00, 0x00, 0x00, 0x02, 0x99 },
        { 0x00, 0x00, 0x00, 0x02, 0xaa },
        { 0x00, 0x00, 0x00, 0x02, 0x55 },
    };
    static unsigned char outputs[][32] = {
        {0xE4, 0x67, 0xF9, 0xA9, 0x55, 0x2B, 0xC7, 0xD3,
         0x15, 0x5A, 0x62, 0x20, 0xAF, 0x9C, 0x19, 0x22,
         0x0E, 0xEE, 0xD4, 0xFF, 0x78, 0xB0, 0xD1, 0xE6,
         0xA1, 0x54, 0x49, 0x91, 0x46, 0x1A, 0x9E, 0x50,
        },
        {0x41, 0x2A, 0xEF, 0xC3, 0x62, 0xA7, 0x28, 0x5F,
         0xC3, 0x96, 0x6C, 0x6A, 0x51, 0x81, 0xE7, 0x60,
         0x5A, 0xE6, 0x75, 0x23, 0x5B, 0x6D, 0x54, 0x9F,
         0xBF, 0xC9, 0xAB, 0x66, 0x30, 0xA4, 0xC6, 0x04,
        },
        {0xFA, 0x62, 0x4F, 0xA0, 0xE5, 0x23, 0x99, 0x3F,
         0xA3, 0x88, 0xAE, 0xFD, 0xC6, 0x7E, 0x67, 0xEB,
         0xCD, 0x8C, 0x08, 0xE8, 0xA0, 0x24, 0x6B, 0x1D,
         0x73, 0xB0, 0xD1, 0xDD, 0x9F, 0xC5, 0x82, 0xB0,
        },
    };
    static unsigned char iv[16] = { 0 };
    unsigned char result[32] = { 0 };

    for (i = 0; i < 3; i++) {
        ret = 0;
        if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_KB)) == NULL) {
            TEST_error("EVP_KDF_KB");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MAC_TYPE, EVP_KDF_KB_MAC_TYPE_CMAC) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KB_MAC_TYPE");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MODE, EVP_KDF_KB_MODE_FEEDBACK) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KB_MODE");
            goto err;
        }
	if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_CIPHER, EVP_camellia_256_cbc()) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_CIPHER");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, input_key, sizeof(input_key)) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KEY");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, constants[i], sizeof(constants[i])) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_SALT");
            goto err;
        }
        if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_SEED, iv, sizeof(iv)) <= 0) {
            TEST_error("EVP_KDF_CTRL_SET_KB_SEED");
            goto err;
        }
        ret = TEST_int_gt(EVP_KDF_derive(kctx, result, sizeof(result)), 0)
            && TEST_mem_eq(result, sizeof(result), outputs[i],
                           sizeof(outputs[i]));
err:
        EVP_KDF_CTX_free(kctx);
        if (ret != 1)
            return ret;
    }
    return ret;
}
#endif

/* Two test vectors from RFC 8009 (AES Encryption with HMAC-SHA2 for Kerberos
 * 5) appendix A. */
static int test_kdf_kbkdf_8009_prf1(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    char *label = "prf", *prf_input = "test";
    static unsigned char input_key[] = {
        0x37, 0x05, 0xD9, 0x60, 0x80, 0xC1, 0x77, 0x28,
        0xA0, 0xE8, 0x00, 0xEA, 0xB6, 0xE0, 0xD2, 0x3C,
    };
    static unsigned char output[] = {
        0x9D, 0x18, 0x86, 0x16, 0xF6, 0x38, 0x52, 0xFE,
        0x86, 0x91, 0x5B, 0xB8, 0x40, 0xB4, 0xA8, 0x86,
        0xFF, 0x3E, 0x6B, 0xB0, 0xF8, 0x19, 0xB4, 0x9B,
        0x89, 0x33, 0x93, 0xD3, 0x93, 0x85, 0x42, 0x95,
    };
    unsigned char result[sizeof(output)] = { 0 };

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_KB)) == NULL) {
        TEST_error("EVP_KDF_KB");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MAC_TYPE, EVP_KDF_KB_MAC_TYPE_HMAC) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KB_MAC_TYPE");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, input_key, sizeof(input_key)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KEY");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, label, strlen(label)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_INFO, prf_input, strlen(prf_input)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KB_INFO");
        goto err;
    }
    ret = TEST_int_gt(EVP_KDF_derive(kctx, result, sizeof(result)), 0)
        && TEST_mem_eq(result, sizeof(result), output,
                           sizeof(output));
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_kbkdf_8009_prf2(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    char *label = "prf", *prf_input = "test";
    static unsigned char input_key[] = {
        0x6D, 0x40, 0x4D, 0x37, 0xFA, 0xF7, 0x9F, 0x9D,
        0xF0, 0xD3, 0x35, 0x68, 0xD3, 0x20, 0x66, 0x98,
        0x00, 0xEB, 0x48, 0x36, 0x47, 0x2E, 0xA8, 0xA0,
        0x26, 0xD1, 0x6B, 0x71, 0x82, 0x46, 0x0C, 0x52,
    };
    static unsigned char output[] = {
        0x98, 0x01, 0xF6, 0x9A, 0x36, 0x8C, 0x2B, 0xF6,
        0x75, 0xE5, 0x95, 0x21, 0xE1, 0x77, 0xD9, 0xA0,
        0x7F, 0x67, 0xEF, 0xE1, 0xCF, 0xDE, 0x8D, 0x3C,
        0x8D, 0x6F, 0x6A, 0x02, 0x56, 0xE3, 0xB1, 0x7D,
        0xB3, 0xC1, 0xB6, 0x2A, 0xD1, 0xB8, 0x55, 0x33,
        0x60, 0xD1, 0x73, 0x67, 0xEB, 0x15, 0x14, 0xD2,
    };
    unsigned char result[sizeof(output)] = { 0 };

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_KB)) == NULL) {
        TEST_error("EVP_KDF_KB");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MAC_TYPE, EVP_KDF_KB_MAC_TYPE_HMAC) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KB_MAC_TYPE");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha384()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, input_key, sizeof(input_key)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KEY");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, label, strlen(label)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SALT");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_INFO, prf_input, strlen(prf_input)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KB_INFO");
        goto err;
    }
    ret = TEST_int_gt(EVP_KDF_derive(kctx, result, sizeof(result)), 0)
        && TEST_mem_eq(result, sizeof(result), output,
                           sizeof(output));
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_krb5kdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];
    static unsigned char key[] = {
        0x42, 0x26, 0x3C, 0x6E, 0x89, 0xF4, 0xFC, 0x28,
        0xB8, 0xDF, 0x68, 0xEE, 0x09, 0x79, 0x9F, 0x15
    };
    static unsigned char constant[] = {
        0x00, 0x00, 0x00, 0x02, 0x99
    };
    static const unsigned char expected[sizeof(out)] = {
        0x34, 0x28, 0x0A, 0x38, 0x2B, 0xC9, 0x27, 0x69,
        0xB2, 0xDA, 0x2F, 0x9E, 0xF0, 0x66, 0x85, 0x4B
    };

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_KRB5KDF)) == NULL) {
        TEST_error("EVP_KDF_KRB5KDF");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_CIPHER, EVP_aes_128_cbc()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_CIPHER");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, key, sizeof(key)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KEY");
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KRB5KDF_CONSTANT, constant, sizeof(constant)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KRB5KDF_CONSTANT");
        goto err;
    }

    ret =
        TEST_int_gt(EVP_KDF_derive(kctx, out, sizeof(out)), 0)
        && TEST_mem_eq(out, sizeof(out), expected, sizeof(expected));

err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int test_kdf_ss_hash(void)
{
    EVP_KDF_CTX *kctx;
    const unsigned char z[] = {
        0x6d,0xbd,0xc2,0x3f,0x04,0x54,0x88,0xe4,0x06,0x27,0x57,0xb0,0x6b,0x9e,
        0xba,0xe1,0x83,0xfc,0x5a,0x59,0x46,0xd8,0x0d,0xb9,0x3f,0xec,0x6f,0x62,
        0xec,0x07,0xe3,0x72,0x7f,0x01,0x26,0xae,0xd1,0x2c,0xe4,0xb2,0x62,0xf4,
        0x7d,0x48,0xd5,0x42,0x87,0xf8,0x1d,0x47,0x4c,0x7c,0x3b,0x18,0x50,0xe9
    };
    const unsigned char other[] = {
        0xa1,0xb2,0xc3,0xd4,0xe5,0x43,0x41,0x56,0x53,0x69,0x64,0x3c,0x83,0x2e,
        0x98,0x49,0xdc,0xdb,0xa7,0x1e,0x9a,0x31,0x39,0xe6,0x06,0xe0,0x95,0xde,
        0x3c,0x26,0x4a,0x66,0xe9,0x8a,0x16,0x58,0x54,0xcd,0x07,0x98,0x9b,0x1e,
        0xe0,0xec,0x3f,0x8d,0xbe
    };
    const unsigned char expected[] = {
        0xa4,0x62,0xde,0x16,0xa8,0x9d,0xe8,0x46,0x6e,0xf5,0x46,0x0b,0x47,0xb8
    };
    unsigned char out[14];

    kctx = EVP_KDF_CTX_new_id(EVP_KDF_SS);

    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha224()) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_MD");
        return 0;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, z, sizeof(z)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_KEY");
        return 0;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSKDF_INFO, other,
                     sizeof(other)) <= 0) {
        TEST_error("EVP_KDF_CTRL_SET_SSKDF_INFO");
        return 0;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        TEST_error("EVP_KDF_derive");
        return 0;
    }

    if (!TEST_mem_eq(out, sizeof(out), expected, sizeof(expected)))
        return 0;

    EVP_KDF_CTX_free(kctx);
    return 1;
}

int setup_tests(void)
{
#ifndef OPENSSL_NO_CAMELLIA
    ADD_TEST(test_kdf_kbkdf_6803_128);
    ADD_TEST(test_kdf_kbkdf_6803_256);
#endif
    ADD_TEST(test_kdf_kbkdf_8009_prf1);
    ADD_TEST(test_kdf_kbkdf_8009_prf2);
    ADD_TEST(test_kdf_tls1_prf);
    ADD_TEST(test_kdf_hkdf);
    ADD_TEST(test_kdf_pbkdf2);
#ifndef OPENSSL_NO_SCRYPT
    ADD_TEST(test_kdf_scrypt);
#endif
    ADD_TEST(test_kdf_krb5kdf);
    ADD_TEST(test_kdf_ss_hash);
    return 1;
}
