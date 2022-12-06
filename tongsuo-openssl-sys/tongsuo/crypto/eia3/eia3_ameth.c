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
#include <openssl/evp.h>
#include "crypto/asn1.h"
#include "crypto/zuc.h"
#include "crypto/evp.h"
#include "eia3_local.h"

/*
 * EIA3 "ASN1" method. This is just here to indicate the maximum
 * EIA3 output length and to free up a EIA3 key.
 */

static int eia3_size(const EVP_PKEY *pkey)
{
    return EIA3_DIGEST_SIZE;
}

static void eia3_key_free(EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *os = EVP_PKEY_get0(pkey);
    if (os != NULL) {
        if (os->data != NULL)
            OPENSSL_cleanse(os->data, os->length);
        ASN1_OCTET_STRING_free(os);
    }
}

static int eia3_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    /* nothing, (including ASN1_PKEY_CTRL_DEFAULT_MD_NID), is supported */
    return -2;
}

static int eia3_pkey_public_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return ASN1_OCTET_STRING_cmp(EVP_PKEY_get0(a), EVP_PKEY_get0(b));
}

static int eia3_set_priv_key(EVP_PKEY *pkey, const unsigned char *priv,
                             size_t len)
{
    ASN1_OCTET_STRING *os;

    if (pkey->pkey.ptr != NULL || len != EVP_ZUC_KEY_SIZE)
        return 0;

    os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return 0;

    if (!ASN1_OCTET_STRING_set(os, priv, len)) {
        ASN1_OCTET_STRING_free(os);
        return 0;
    }

    pkey->pkey.ptr = os;
    return 1;
}

static int eia3_get_priv_key(const EVP_PKEY *pkey, unsigned char *priv,
                             size_t *len)
{
    ASN1_OCTET_STRING *os = (ASN1_OCTET_STRING *)pkey->pkey.ptr;

    if (priv == NULL) {
        *len = EVP_ZUC_KEY_SIZE;
        return 1;
    }

    if (os == NULL || *len < EVP_ZUC_KEY_SIZE)
        return 0;

    memcpy(priv, ASN1_STRING_get0_data(os), ASN1_STRING_length(os));
    *len = EVP_ZUC_KEY_SIZE;

    return 1;
}

const EVP_PKEY_ASN1_METHOD eia3_asn1_meth = {
    EVP_PKEY_EIA3,
    EVP_PKEY_EIA3,
    0,

    "EIA3",
    "ZUC 128-EIA3 method",

    0, 0, eia3_pkey_public_cmp, 0,

    0, 0, 0,

    eia3_size,
    0, 0,
    0, 0, 0, 0, 0, 0, 0,

    eia3_key_free,
    eia3_pkey_ctrl,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    eia3_set_priv_key,
    NULL,
    eia3_get_priv_key,
    NULL,
};
