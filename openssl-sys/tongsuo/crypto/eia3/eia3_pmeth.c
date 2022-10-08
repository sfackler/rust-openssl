/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto/zuc.h"
#include "crypto/evp.h"
#include "eia3_local.h"

/* EIA3 pkey context structure */

typedef struct {
    ASN1_OCTET_STRING key;
    ASN1_OCTET_STRING iv;
    EIA3_CTX ctx;
} EIA3_PKEY_CTX;

static int pkey_eia3_init(EVP_PKEY_CTX *ctx)
{
    EIA3_PKEY_CTX *pctx;

    if ((pctx = OPENSSL_zalloc(sizeof(*pctx))) == NULL) {
        CRYPTOerr(CRYPTO_F_PKEY_EIA3_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    pctx->key.type = V_ASN1_OCTET_STRING;
    pctx->iv.type = V_ASN1_OCTET_STRING;

    EVP_PKEY_CTX_set_data(ctx, pctx);
    EVP_PKEY_CTX_set0_keygen_info(ctx, NULL, 0);
    return 1;
}

static void pkey_eia3_cleanup(EVP_PKEY_CTX *ctx)
{
    EIA3_PKEY_CTX *pctx = EVP_PKEY_CTX_get_data(ctx);

    if (pctx != NULL) {
        OPENSSL_clear_free(pctx->key.data, pctx->key.length);
        OPENSSL_clear_free(pctx->iv.data, pctx->iv.length);
        OPENSSL_clear_free(pctx, sizeof(*pctx));
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

static int pkey_eia3_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    EIA3_PKEY_CTX *sctx, *dctx;

    /* allocate memory for dst->data and a new EIA3_CTX in dst->data->ctx */
    if (!pkey_eia3_init(dst))
        return 0;
    sctx = EVP_PKEY_CTX_get_data(src);
    dctx = EVP_PKEY_CTX_get_data(dst);
    if (ASN1_STRING_get0_data(&sctx->key) != NULL &&
        !ASN1_STRING_copy(&dctx->key, &sctx->key)) {
        /* cleanup and free the EIA3_PKEY_CTX in dst->data */
        pkey_eia3_cleanup(dst);
        return 0;
    }
    if (ASN1_STRING_get0_data(&sctx->iv) != NULL &&
        !ASN1_STRING_copy(&dctx->iv, &sctx->iv)) {
        /* cleanup and free the EIA3_PKEY_CTX in dst->data */
        pkey_eia3_cleanup(dst);
        return 0;
    }
    memcpy(&dctx->ctx, &sctx->ctx, sizeof(EIA3_CTX));
    return 1;
}

static int pkey_eia3_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *key;
    EIA3_PKEY_CTX *pctx = EVP_PKEY_CTX_get_data(ctx);

    if (ASN1_STRING_get0_data(&pctx->key) == NULL)
        return 0;
    key = ASN1_OCTET_STRING_dup(&pctx->key);
    if (key == NULL)
        return 0;
    return EVP_PKEY_assign_EIA3(pkey, key);
}

static int int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    EIA3_PKEY_CTX *pctx = EVP_PKEY_CTX_get_data(EVP_MD_CTX_pkey_ctx(ctx));

    return EIA3_Update(&pctx->ctx, data, count);
}

static int eia3_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    EIA3_PKEY_CTX *pctx = ctx->data;
    ASN1_OCTET_STRING *key = (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;

    if (key->length != EVP_ZUC_KEY_SIZE)
        return 0;

    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_update_fn(mctx, int_update);

    if (!ASN1_OCTET_STRING_set(&pctx->key, key->data, key->length))
        return 0;

    return EIA3_Init(&pctx->ctx, key->data, NULL);
}

static int eia3_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                            EVP_MD_CTX *mctx)
{
    EIA3_PKEY_CTX *pctx = ctx->data;

    *siglen = EIA3_DIGEST_SIZE;
    if (sig != NULL)
        EIA3_Final(&pctx->ctx, sig);
    return 1;
}

static int pkey_eia3_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    EIA3_PKEY_CTX *pctx = EVP_PKEY_CTX_get_data(ctx);
    const unsigned char *key, *iv;
    size_t len;

    switch (type) {

    case EVP_PKEY_CTRL_MD:
        /* ignore */
        break;

    case EVP_PKEY_CTRL_SET_IV:
        iv = p2;
        len = p1;
        if (iv == NULL || len != EVP_ZUC_KEY_SIZE ||
            !ASN1_OCTET_STRING_set(&pctx->iv, iv, len)) {
            return 0;
        }

        key = ASN1_STRING_get0_data(&pctx->key);
        if (key != NULL)
            EIA3_Init(&pctx->ctx, key, iv);
        break;
    case EVP_PKEY_CTRL_SET_MAC_KEY:
    case EVP_PKEY_CTRL_DIGESTINIT:
        if (type == EVP_PKEY_CTRL_SET_MAC_KEY) {
            /* user explicitly setting the key */
            key = p2;
            len = p1;
        } else {
            /* user indirectly setting the key via EVP_DigestSignInit */
            key = EVP_PKEY_get0_eia3(EVP_PKEY_CTX_get0_pkey(ctx), &len);
        }
        if (key == NULL || len != EVP_ZUC_KEY_SIZE ||
            !ASN1_OCTET_STRING_set(&pctx->key, key, len))
            return 0;

        EIA3_Init(&pctx->ctx, ASN1_STRING_get0_data(&pctx->key),
                  ASN1_STRING_get0_data(&pctx->iv));
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_eia3_ctrl_str(EVP_PKEY_CTX *ctx,
                                  const char *type, const char *value)
{
    if (value == NULL)
        return 0;
    if (strcmp(type, "iv") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_SET_IV, value);
    if (strcmp(type, "key") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, value);
    return -2;
}

const EVP_PKEY_METHOD eia3_pkey_meth = {
    EVP_PKEY_EIA3,
    EVP_PKEY_FLAG_SIGCTX_CUSTOM, /* we don't deal with a separate MD */
    pkey_eia3_init,
    pkey_eia3_copy,
    pkey_eia3_cleanup,

    0, 0,

    0,
    pkey_eia3_keygen,

    0, 0,

    0, 0,

    0, 0,

    eia3_signctx_init,
    eia3_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_eia3_ctrl,
    pkey_eia3_ctrl_str
};
