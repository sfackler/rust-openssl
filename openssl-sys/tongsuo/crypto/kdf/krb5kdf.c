/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "kdf_local.h"

/* KRB5 KDF defined in RFC 3961, Section 5.1 */

static int KRB5KDF(const EVP_CIPHER *cipher,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *constant, size_t constant_len,
                   unsigned char *okey, size_t okey_len);

struct evp_kdf_impl_st {
    const EVP_CIPHER *cipher;
    unsigned char *key;
    size_t key_len;
    unsigned char *constant;
    size_t constant_len;
};

static void krb5kdf_reset(EVP_KDF_IMPL *ctx);

static EVP_KDF_IMPL *krb5kdf_new(void)
{
    EVP_KDF_IMPL *ctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        KDFerr(KDF_F_KRB5KDF_NEW, ERR_R_MALLOC_FAILURE);
    return ctx;
}

static void krb5kdf_free(EVP_KDF_IMPL *ctx)
{
    krb5kdf_reset(ctx);
    OPENSSL_free(ctx);
}

static void krb5kdf_reset(EVP_KDF_IMPL *ctx)
{
    OPENSSL_clear_free(ctx->key, ctx->key_len);
    OPENSSL_clear_free(ctx->constant, ctx->constant_len);
    memset(ctx, 0, sizeof(*ctx));
}

static int krb5kdf_derive(EVP_KDF_IMPL *ctx, unsigned char *key,
                              size_t keylen)
{
    if (ctx->cipher == NULL) {
        KDFerr(KDF_F_KRB5KDF_DERIVE, KDF_R_MISSING_CIPHER);
        return 0;
    }
    if (ctx->key == NULL) {
        KDFerr(KDF_F_KRB5KDF_DERIVE, KDF_R_MISSING_KEY);
        return 0;
    }
    if (ctx->constant == NULL) {
        KDFerr(KDF_F_KRB5KDF_DERIVE, KDF_R_MISSING_CONSTANT);
        return 0;
    }
    return KRB5KDF(ctx->cipher, ctx->key, ctx->key_len,
                   ctx->constant, ctx->constant_len,
                   key, keylen);
}

static size_t krb5kdf_size(EVP_KDF_IMPL *ctx)
{
    if (ctx->cipher != NULL)
        return EVP_CIPHER_key_length(ctx->cipher);
    else
        return EVP_MAX_KEY_LENGTH;
}


static int krb5kdf_parse_buffer_arg(unsigned char **dst, size_t *dst_len,
                                       va_list args)
{
    const unsigned char *p;
    size_t len;

    p = va_arg(args, const unsigned char *);
    len = va_arg(args, size_t);
    OPENSSL_clear_free(*dst, *dst_len);
    if (len == 0) {
        *dst = NULL;
        *dst_len = 0;
        return 1;
    }

    *dst = OPENSSL_memdup(p, len);
    if (*dst == NULL)
        return 0;

    *dst_len = len;
    return 1;
}

static int krb5kdf_ctrl(EVP_KDF_IMPL *ctx, int cmd, va_list args)
{
    switch (cmd) {
    case EVP_KDF_CTRL_SET_CIPHER:
        ctx->cipher = va_arg(args, const EVP_CIPHER *);
        if (ctx->cipher == NULL)
            return 0;

        return 1;

    case EVP_KDF_CTRL_SET_KEY:
        return krb5kdf_parse_buffer_arg(&ctx->key,
                                      &ctx->key_len, args);

    case EVP_KDF_CTRL_SET_KRB5KDF_CONSTANT:
        return krb5kdf_parse_buffer_arg(&ctx->constant,
                                           &ctx->constant_len, args);
    default:
        return -2;

    }
}

static int krb5kdf_ctrl_str(EVP_KDF_IMPL *ctx, const char *type,
                               const char *value)
{
    if (value == NULL) {
        KDFerr(KDF_F_KRB5KDF_CTRL_STR, KDF_R_VALUE_MISSING);
        return 0;
    }

    if (strcmp(type, "cipher") == 0)
        return kdf_cipher2ctrl(ctx, krb5kdf_ctrl, EVP_KDF_CTRL_SET_CIPHER, value);

    if (strcmp(type, "key") == 0)
        return kdf_str2ctrl(ctx, krb5kdf_ctrl,
                            EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "hexkey") == 0)
        return kdf_hex2ctrl(ctx, krb5kdf_ctrl,
                            EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "constant") == 0)
        return kdf_str2ctrl(ctx, krb5kdf_ctrl,
                            EVP_KDF_CTRL_SET_KRB5KDF_CONSTANT, value);

    if (strcmp(type, "hexconstant") == 0)
        return kdf_hex2ctrl(ctx, krb5kdf_ctrl,
                            EVP_KDF_CTRL_SET_KRB5KDF_CONSTANT, value);

    KDFerr(KDF_F_KRB5KDF_CTRL_STR, KDF_R_UNKNOWN_PARAMETER_TYPE);
    return -2;
}


#ifndef OPENSSL_NO_DES
/*
 * DES3 is a special case, it requires a random-to-key function and its
 * input truncated to 21 bytes of the 24 produced by the cipher.
 * See RFC3961 6.3.1
 */
static int fixup_des3_key(unsigned char *key)
{
    unsigned char *cblock;
    int i, j;

    for (i = 2; i >= 0; i--) {
        cblock = &key[i * 8];
        memmove(cblock, &key[i * 7], 7);
        cblock[7] = 0;
        for (j = 0; j < 7; j++)
            cblock[7] |= (cblock[j] & 1) << (j + 1);
        DES_set_odd_parity((DES_cblock *)cblock);
    }

    /* fail if keys are such that triple des degrades to single des */
    if (CRYPTO_memcmp(&key[0], &key[8], 8) == 0 ||
        CRYPTO_memcmp(&key[8], &key[16], 8) == 0) {
        return 0;
    }

    return 1;
}
#endif

/*
 * N-fold(K) where blocksize is N, and constant_len is K
 * Note: Here |= denotes concatenation
 *
 * L = lcm(N,K)
 * R = L/K
 *
 * for r: 1 -> R
 *   s |= constant rot 13*(r-1))
 *
 * block = 0
 * for k: 1 -> K
 *   block += s[N(k-1)..(N-1)k] (one's complement addition)
 *
 * Optimizing for space we compute:
 * for each l in L-1 -> 0:
 *   s[l] = (constant rot 13*(l/K))[l%k]
 *   block[l % N] += s[l] (with carry)
 * finally add carry if any
 */
static void n_fold(unsigned char *block, unsigned int blocksize,
                   const unsigned char *constant, size_t constant_len)
{
    unsigned int tmp, gcd, remainder, lcm, carry;
    int b, l;

    if (constant_len == blocksize) {
        memcpy(block, constant, constant_len);
        return;
    }

    /* Least Common Multiple of lengths: LCM(a,b)*/
    gcd = blocksize;
    remainder = constant_len;
    /* Calculate Great Common Divisor first GCD(a,b) */
    while (remainder != 0) {
        tmp = gcd % remainder;
        gcd = remainder;
        remainder = tmp;
    }
    /* resulting a is the GCD, LCM(a,b) = |a*b|/GCD(a,b) */
    lcm = blocksize * constant_len / gcd;

    /* now spread out the bits */
    memset(block, 0, blocksize);

    /* last to first to be able to bring carry forward */
    carry = 0;
    for (l = lcm - 1; l >= 0; l--) {
        unsigned int rotbits, rshift, rbyte;

        /* destination byte in block is l % N */
        b = l % blocksize;
        /* Our virtual s buffer is R = L/K long (K = constant_len) */
        /* So we rotate backwards from R-1 to 0 (none) rotations */
        rotbits = 13 * (l / constant_len);
        /* find the byte on s where rotbits falls onto */
        rbyte = l - (rotbits / 8);
        /* calculate how much shift on that byte */
        rshift = rotbits & 0x07;
        /* rbyte % constant_len gives us the unrotated byte in the
         * constant buffer, get also the previous byte then
         * appropriately shift them to get the rotated byte we need */
        tmp = (constant[(rbyte-1) % constant_len] << (8 - rshift)
               | constant[rbyte % constant_len] >> rshift)
              & 0xff;
        /* add with carry to any value placed by previous passes */
        tmp += carry + block[b];
        block[b] = tmp & 0xff;
        /* save any carry that may be left */
        carry = tmp >> 8;
    }

    /* if any carry is left at the end, add it through the number */
    for (b = blocksize - 1; b >= 0 && carry != 0; b--) {
        carry += block[b];
        block[b] = carry & 0xff;
        carry >>= 8;
    }
}

static int cipher_init(EVP_CIPHER_CTX *ctx,
                       const EVP_CIPHER *cipher,
                       const unsigned char *key, size_t key_len)
{
    int klen, ret;

    ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
    if (!ret)
        goto out;
    /* set the key len for the odd variable key len cipher */
    klen = EVP_CIPHER_CTX_key_length(ctx);
    if (key_len != (size_t)klen) {
        ret = EVP_CIPHER_CTX_set_key_length(ctx, key_len);
        if (!ret)
            goto out;
    }
    /* we never want padding, either the length requested is a multiple of
     * the cipher block size or we are passed a cipher that can cope with
     * partial blocks via techniques like cipher text stealing */
    ret = EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!ret)
        goto out;

out:
    return ret;
}

static int KRB5KDF(const EVP_CIPHER *cipher,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *constant, size_t constant_len,
                   unsigned char *okey, size_t okey_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char block[EVP_MAX_BLOCK_LENGTH * 2];
    unsigned char *plainblock, *cipherblock;
    size_t blocksize;
    size_t cipherlen;
    size_t osize;
    int ret;

#ifndef OPENSSL_NO_DES
    int des3_no_fixup = 0;
#endif

    if (key_len != okey_len) {
        /* special case for 3des, where the caller may be requesting
         * the random raw key, instead of the fixed up key  */
        if (EVP_CIPHER_nid(cipher) == NID_des_ede3_cbc &&
            key_len == 24 && okey_len == 21) {
#ifndef OPENSSL_NO_DES
		des3_no_fixup = 1;
#endif
        } else {
            KDFerr(KDF_F_KRB5KDF, KDF_R_WRONG_OUTPUT_BUFFER_SIZE);
            return 0;
        }
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    ret = cipher_init(ctx, cipher, key, key_len);
    if (!ret)
        goto out;

    /* Initialize input block */
    blocksize = EVP_CIPHER_CTX_block_size(ctx);

    if (constant_len == 0 || constant_len > blocksize) {
        KDFerr(KDF_F_KRB5KDF, KDF_R_INVALID_CONSTANT_LENGTH);
        ret = 0;
        goto out;
    }

    n_fold(block, blocksize, constant, constant_len);
    plainblock = block;
    cipherblock = block + EVP_MAX_BLOCK_LENGTH;

    for (osize = 0; osize < okey_len; osize += cipherlen) {
        int olen;

        ret = EVP_EncryptUpdate(ctx, cipherblock, &olen,
                                plainblock, blocksize);
        if (!ret)
            goto out;
        cipherlen = olen;
        ret = EVP_EncryptFinal_ex(ctx, cipherblock, &olen);
        if (!ret)
            goto out;
        if (olen != 0) {
            KDFerr(KDF_F_KRB5KDF, KDF_R_WRONG_FINAL_BLOCK_LENGTH);
            ret = 0;
            goto out;
        }

        /* write cipherblock out */
        if (cipherlen > okey_len - osize)
            cipherlen = okey_len - osize;
        memcpy(okey + osize, cipherblock, cipherlen);

        if (okey_len > osize + cipherlen) {
            /* we need to reinitialize cipher context per spec */
            ret = EVP_CIPHER_CTX_reset(ctx);
            if (!ret)
                goto out;
            ret = cipher_init(ctx, cipher, key, key_len);
            if (!ret)
                goto out;

            /* also swap block offsets so last ciphertext becomes new
             * plaintext */
            plainblock = cipherblock;
            if (cipherblock == block) {
                cipherblock += EVP_MAX_BLOCK_LENGTH;
            } else {
                cipherblock = block;
            }
        }
    }

#ifndef OPENSSL_NO_DES
    if (EVP_CIPHER_nid(cipher) == NID_des_ede3_cbc && !des3_no_fixup) {
        ret = fixup_des3_key(okey);
        if (!ret) {
            KDFerr(KDF_F_KRB5KDF, KDF_R_FAILED_TO_GENERATE_KEY);
            goto out;
        }
    }
#endif

    ret = 1;

out:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(block, EVP_MAX_BLOCK_LENGTH * 2);
    return ret;
}

const EVP_KDF_METHOD krb5kdf_kdf_meth = {
    EVP_KDF_KRB5KDF,
    krb5kdf_new,
    krb5kdf_free,
    krb5kdf_reset,
    krb5kdf_ctrl,
    krb5kdf_ctrl_str,
    krb5kdf_size,
    krb5kdf_derive,
};

