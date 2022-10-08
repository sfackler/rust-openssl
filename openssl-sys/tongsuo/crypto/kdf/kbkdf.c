/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This implements https://csrc.nist.gov/publications/detail/sp/800-108/final
 * section 5.1 ("counter mode") and section 5.2 ("feedback mode") in both HMAC
 * and CMAC.  That document does not name the KDFs it defines; the name is
 * derived from
 * https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation
 *
 * Note that section 5.3 ("double-pipeline mode") is not implemented, though
 * it would be possible to do so in the future.
 *
 * These versions all assume the counter is used.  It would be relatively
 * straightforward to expose a configuration handle should the need arise.
 *
 * Variable names attempt to match those of SP800-108.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/kdf.h>

#include "internal/numbers.h"
#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "kdf_local.h"

#include "e_os.h"

#ifdef MIN
# undef MIN
#endif
#define MIN(a, b) ((a) < (b)) ? (a) : (b)

typedef struct {
    int mac_type;
    union {
        HMAC_CTX *hmac;
#ifndef OPENSSL_NO_CMAC
        CMAC_CTX *cmac;
#endif
    } m;
} MAC_CTX;

/* Our context structure. */
struct evp_kdf_impl_st {
    int mode;

    MAC_CTX *ctx_init;

    const EVP_CIPHER *cipher;
    const EVP_MD *md;

    /* Names are lowercased versions of those found in SP800-108. */
    unsigned char *ki;
    size_t ki_len;
    unsigned char *label;
    size_t label_len;
    unsigned char *context;
    size_t context_len;
    unsigned char *iv;
    size_t iv_len;
};

static MAC_CTX *EVP_MAC_CTX_new(int mac_type)
{
    MAC_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->mac_type = mac_type;
    if (mac_type == EVP_KDF_KB_MAC_TYPE_HMAC) {
        if ((ctx->m.hmac = HMAC_CTX_new()) == NULL)
            goto err;
    } else {
#ifndef OPENSSL_NO_CMAC
        if ((ctx->m.cmac = CMAC_CTX_new()) == NULL)
            goto err;
#endif
    }
    return ctx;

err:
    OPENSSL_free(ctx);
    return NULL;
}

static void EVP_MAC_CTX_free(MAC_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->mac_type == EVP_KDF_KB_MAC_TYPE_HMAC)
        HMAC_CTX_free(ctx->m.hmac);
    else
#ifndef OPENSSL_NO_CMAC
        CMAC_CTX_free(ctx->m.cmac);
#endif
    OPENSSL_free(ctx);
}

static MAC_CTX *EVP_MAC_CTX_dup(MAC_CTX *sctx)
{
    MAC_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*sctx));
    if (ctx == NULL)
        return NULL;

    ctx->mac_type = sctx->mac_type;
    if (sctx->mac_type == EVP_KDF_KB_MAC_TYPE_HMAC) {
        if ((ctx->m.hmac = HMAC_CTX_new()) == NULL
            || HMAC_CTX_copy(ctx->m.hmac, sctx->m.hmac) <= 0)
            goto err;
    } else {
#ifndef OPENSSL_NO_CMAC
        if ((ctx->m.cmac = CMAC_CTX_new()) == NULL
            || CMAC_CTX_copy(ctx->m.cmac, sctx->m.cmac) <= 0)
            goto err;
#endif
    }
    return ctx;

err:
    EVP_MAC_CTX_free(ctx);
    return NULL;
}

static size_t EVP_MAC_size(MAC_CTX *ctx)
{
    if (ctx->mac_type == EVP_KDF_KB_MAC_TYPE_HMAC) {
        const EVP_MD *md;

        if (ctx->m.hmac == NULL)
            return 0;
        if ((md = HMAC_CTX_get_md(ctx->m.hmac)) == NULL)
            return 0;
        return (size_t)EVP_MD_size(md);
    } else {
#ifndef OPENSSL_NO_CMAC
        const EVP_CIPHER_CTX *cctx;

        if (ctx->m.cmac == NULL)
            return 0;
        if ((cctx = CMAC_CTX_get0_cipher_ctx(ctx->m.cmac)) == NULL)
            return 0;
        return EVP_CIPHER_CTX_block_size(cctx);
#endif
    }

    return 0;
}

static int EVP_MAC_update(MAC_CTX *ctx, const unsigned char *data,
                          size_t datalen)
{
    if (ctx->mac_type == EVP_KDF_KB_MAC_TYPE_HMAC)
        return HMAC_Update(ctx->m.hmac, data, datalen);
    else {
#ifndef OPENSSL_NO_CMAC
        return CMAC_Update(ctx->m.cmac, data, datalen);
#endif
    }
    return 0;
}

static int EVP_MAC_final(MAC_CTX *ctx, unsigned char *out,
                         size_t *outl, size_t outsize)
{
    if (outsize != EVP_MAC_size(ctx))
        /* we do not cope with anything else */
        return 0;

    if (ctx->mac_type == EVP_KDF_KB_MAC_TYPE_HMAC) {
        unsigned int intsize = (unsigned int)outsize;
        int ret;

        ret = HMAC_Final(ctx->m.hmac, out, &intsize);
        if (outl != NULL)
            *outl = intsize;
        return ret;
    } else {
#ifndef OPENSSL_NO_CMAC
        size_t size = outsize;
        int ret;
        ret = CMAC_Final(ctx->m.cmac, out, &size);
        if (outl != NULL)
            *outl = size;
        return ret;
#endif
    }

    return 0;
}

static int evp_mac_init(MAC_CTX *ctx, const EVP_MD *md,
                        const EVP_CIPHER *cipher, unsigned char *key, size_t keylen)
{
    if (ctx->mac_type == EVP_KDF_KB_MAC_TYPE_HMAC) {
        if (md == NULL)
            return 0;
        return HMAC_Init_ex(ctx->m.hmac, key, (int)keylen, md, NULL);
    } else {
#ifndef OPENSSL_NO_CMAC
        if (cipher == NULL)
            return 0;
        return CMAC_Init(ctx->m.cmac, key, keylen, cipher, NULL);
#endif
    }

    return 0;
}

static void kbkdf_reset(EVP_KDF_IMPL *ctx);

/* Not all platforms have htobe32(). */
static uint32_t be32(uint32_t host)
{
    uint32_t big = 0;
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    if (!is_endian.little)
        return host;

    big |= (host & 0xff000000) >> 24;
    big |= (host & 0x00ff0000) >> 8;
    big |= (host & 0x0000ff00) << 8;
    big |= (host & 0x000000ff) << 24;
    return big;
}

static EVP_KDF_IMPL *kbkdf_new(void)
{
    EVP_KDF_IMPL *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        KDFerr(KDF_F_KBKDF_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ctx;
}

static void kbkdf_free(EVP_KDF_IMPL *ctx)
{
    kbkdf_reset(ctx);
    OPENSSL_free(ctx);
}

static void kbkdf_reset(EVP_KDF_IMPL *ctx)
{
    EVP_MAC_CTX_free(ctx->ctx_init);
    OPENSSL_clear_free(ctx->context, ctx->context_len);
    OPENSSL_clear_free(ctx->label, ctx->label_len);
    OPENSSL_clear_free(ctx->ki, ctx->ki_len);
    OPENSSL_clear_free(ctx->iv, ctx->iv_len);
    memset(ctx, 0, sizeof(*ctx));
}

/* SP800-108 section 5.1 or section 5.2 depending on mode. */
static int derive(MAC_CTX *ctx_init, int mode, unsigned char *iv,
                  size_t iv_len, unsigned char *label, size_t label_len,
                  unsigned char *context, size_t context_len,
                  unsigned char *k_i, size_t h, uint32_t l, unsigned char *ko,
                  size_t ko_len)
{
    int ret = 0;
    MAC_CTX *ctx = NULL;
    size_t written = 0, to_write, k_i_len = iv_len;
    const unsigned char zero = 0;
    uint32_t counter, i;

    /* Setup K(0) for feedback mode. */
    if (iv_len > 0)
        memcpy(k_i, iv, iv_len);

    for (counter = 1; written < ko_len; counter++) {
        i = be32(counter);

        ctx = EVP_MAC_CTX_dup(ctx_init);
        if (ctx == NULL)
            goto done;

        /* Perform feedback, if appropriate. */
        if (mode == EVP_KDF_KB_MODE_FEEDBACK && !EVP_MAC_update(ctx, k_i, k_i_len))
            goto done;

        if (!EVP_MAC_update(ctx, (unsigned char *)&i, 4)
            || !EVP_MAC_update(ctx, label, label_len)
            || !EVP_MAC_update(ctx, &zero, 1)
            || !EVP_MAC_update(ctx, context, context_len)
            || !EVP_MAC_update(ctx, (unsigned char *)&l, 4)
            || !EVP_MAC_final(ctx, k_i, NULL, h))
            goto done;

        to_write = ko_len - written;
        memcpy(ko + written, k_i, MIN(to_write, h));
        written += h;

        k_i_len = h;
        EVP_MAC_CTX_free(ctx);
        ctx = NULL;
    }

    ret = 1;
done:
    EVP_MAC_CTX_free(ctx);
    return ret;
}

static int kbkdf_derive(EVP_KDF_IMPL *ctx, unsigned char *key, size_t keylen)
{
    int ret = 0;
    unsigned char *k_i = NULL;
    uint32_t l = be32(keylen * 8);
    size_t h = 0;

    /* label, context, and iv are permitted to be empty.  Check everything
     * else. */
    if (ctx->ctx_init == NULL
        || evp_mac_init(ctx->ctx_init, ctx->md, ctx->cipher, ctx->ki, ctx->ki_len) <= 0) {
        if (ctx->ki_len == 0 || ctx->ki == NULL) {
            KDFerr(KDF_F_KBKDF_DERIVE, KDF_R_MISSING_KEY);
            return 0;
        }
        /* Could either be missing MAC or missing message digest or missing
         * cipher - arbitrarily, I pick this one. */
        KDFerr(KDF_F_KBKDF_DERIVE, KDF_R_MISSING_PARAMETER);
        return 0;
    }

    h = EVP_MAC_size(ctx->ctx_init);
    if (h == 0)
        goto done;
    if (ctx->iv_len != 0 && ctx->iv_len != h) {
        KDFerr(KDF_F_KBKDF_DERIVE, KDF_R_INVALID_SEED_LENGTH);
        goto done;
    }

    k_i = OPENSSL_zalloc(h);
    if (k_i == NULL)
        goto done;

    ret = derive(ctx->ctx_init, ctx->mode, ctx->iv, ctx->iv_len, ctx->label,
                 ctx->label_len, ctx->context, ctx->context_len, k_i, h, l,
                 key, keylen);
done:
    if (ret != 1)
        OPENSSL_cleanse(key, keylen);
    OPENSSL_clear_free(k_i, h);
    return ret;
}

static size_t kbkdf_size(EVP_KDF_IMPL *ctx)
{
    return UINT32_MAX/8;
}

static int kbkdf_parse_buffer_arg(unsigned char **dst, size_t *dst_len,
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

static int kbkdf_ctrl(EVP_KDF_IMPL *ctx, int cmd, va_list args)
{
    int t;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_MD:
        ctx->md = va_arg(args, const EVP_MD *);
        if (ctx->md == NULL)
            return 0;

        return 1;

    case EVP_KDF_CTRL_SET_CIPHER:
        ctx->cipher = va_arg(args, const EVP_CIPHER *);
        if (ctx->cipher == NULL)
            return 0;

        return 1;

    case EVP_KDF_CTRL_SET_KEY:
        return kbkdf_parse_buffer_arg(&ctx->ki,
                                      &ctx->ki_len, args);

    case EVP_KDF_CTRL_SET_SALT:
        return kbkdf_parse_buffer_arg(&ctx->label,
                                           &ctx->label_len, args);

    case EVP_KDF_CTRL_SET_KB_INFO:
        return kbkdf_parse_buffer_arg(&ctx->context,
                                           &ctx->context_len, args);

    case EVP_KDF_CTRL_SET_KB_SEED:
        return kbkdf_parse_buffer_arg(&ctx->iv,
                                           &ctx->iv_len, args);

    case EVP_KDF_CTRL_SET_KB_MODE:
        t = va_arg(args, int);
        if (t != EVP_KDF_KB_MODE_COUNTER && t != EVP_KDF_KB_MODE_FEEDBACK ) {
            KDFerr(KDF_F_KBKDF_CTRL, KDF_R_VALUE_ERROR);
            return 0;
        }
        ctx->mode = t;
        return 1;

    case EVP_KDF_CTRL_SET_KB_MAC_TYPE:
        t = va_arg(args, int);
        if (t != EVP_KDF_KB_MAC_TYPE_HMAC && t != EVP_KDF_KB_MAC_TYPE_CMAC ) {
            KDFerr(KDF_F_KBKDF_CTRL, KDF_R_VALUE_ERROR);
            return 0;
        }

        if (ctx->ctx_init != NULL) {
            EVP_MAC_CTX_free(ctx->ctx_init);
        }
        ctx->ctx_init = EVP_MAC_CTX_new(t);
        if (ctx->ctx_init == NULL) {
            KDFerr(KDF_F_KBKDF_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        return 1;

    default:
        return -2;

    }
}

static int kbkdf_ctrl_str(EVP_KDF_IMPL *ctx, const char *type,
                               const char *value)
{
    if (value == NULL) {
        KDFerr(KDF_F_KBKDF_CTRL_STR, KDF_R_VALUE_MISSING);
        return 0;
    }

    if (strcmp(type, "digest") == 0)
        return kdf_md2ctrl(ctx, kbkdf_ctrl, EVP_KDF_CTRL_SET_MD, value);
    /* alias, for historical reasons */
    if (strcmp(type, "md") == 0)
        return kdf_md2ctrl(ctx, kbkdf_ctrl, EVP_KDF_CTRL_SET_MD, value);

    if (strcmp(type, "cipher") == 0)
        return kdf_cipher2ctrl(ctx, kbkdf_ctrl, EVP_KDF_CTRL_SET_CIPHER, value);

    if (strcmp(type, "key") == 0)
        return kdf_str2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "hexkey") == 0)
        return kdf_hex2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_KEY, value);

    if (strcmp(type, "salt") == 0)
        return kdf_str2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_SALT, value);

    if (strcmp(type, "hexsalt") == 0)
        return kdf_hex2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_SALT, value);

    if (strcmp(type, "info") == 0)
        return kdf_str2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_KB_INFO, value);

    if (strcmp(type, "hexinfo") == 0)
        return kdf_hex2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_KB_INFO, value);

    if (strcmp(type, "seed") == 0)
        return kdf_str2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_KB_SEED, value);

    if (strcmp(type, "hexseed") == 0)
        return kdf_hex2ctrl(ctx, kbkdf_ctrl,
                            EVP_KDF_CTRL_SET_KB_SEED, value);

    if (strcmp(type, "mode") == 0) {
        int mode;

        if (strcasecmp(value, "counter") == 0) {
            mode = EVP_KDF_KB_MODE_COUNTER;
        } else if (strcasecmp(value, "feedback") == 0) {
            mode = EVP_KDF_KB_MODE_FEEDBACK;
        } else {
            KDFerr(KDF_F_KBKDF_CTRL_STR, KDF_R_VALUE_ERROR);
            return 0;
        }

        return call_ctrl(kbkdf_ctrl, ctx, EVP_KDF_CTRL_SET_KB_MODE,
                         mode);
    }

    if (strcmp(type, "mac_type") == 0) {
        int mac_type;

        if (strcasecmp(value, "hmac") == 0) {
            mac_type = EVP_KDF_KB_MAC_TYPE_HMAC;
        } else if (strcasecmp(value, "cmac") == 0) {
            mac_type = EVP_KDF_KB_MAC_TYPE_CMAC;
        } else {
            KDFerr(KDF_F_KBKDF_CTRL_STR, KDF_R_VALUE_ERROR);
            return 0;
        }

        return call_ctrl(kbkdf_ctrl, ctx, EVP_KDF_CTRL_SET_KB_MAC_TYPE,
                         mac_type);
    }

    KDFerr(KDF_F_KBKDF_CTRL_STR, KDF_R_UNKNOWN_PARAMETER_TYPE);
    return -2;
}

const EVP_KDF_METHOD kb_kdf_meth = {
    EVP_KDF_KB,
    kbkdf_new,
    kbkdf_free,
    kbkdf_reset,
    kbkdf_ctrl,
    kbkdf_ctrl_str,
    kbkdf_size,
    kbkdf_derive,
};

