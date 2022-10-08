/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include "ec_elgamal.h"
#include <string.h>

#define EC_ELGAMAL_MSG_BITS 32
#define EC_ELGAMAL_ECDLP_BABY_BITS 15
#define EC_ELGAMAL_ECDLP_GIANT_BITS (EC_ELGAMAL_MSG_BITS-EC_ELGAMAL_ECDLP_BABY_BITS)

static EC_ELGAMAL_dec_tbl_entry *EC_ELGAMAL_dec_tbl_entry_new(EC_ELGAMAL_CTX *ctx,
                                                              EC_POINT *point,
                                                              int32_t value);
static void EC_ELGAMAL_dec_tbl_entry_free(EC_ELGAMAL_dec_tbl_entry *entry);

static unsigned long EC_ELGAMAL_dec_tbl_entry_hash(const EC_ELGAMAL_dec_tbl_entry *e)
{
    int i = e->key_len;
    unsigned char *p = e->key;

    while (*p == 0 && i-- > 0)
        p++;

    return openssl_lh_strcasehash((const char *)p);
}

static int EC_ELGAMAL_dec_tbl_entry_cmp(const EC_ELGAMAL_dec_tbl_entry *a,
                                        const EC_ELGAMAL_dec_tbl_entry *b)
{
    if (a->key_len != b->key_len)
        return -1;

    return memcmp(a->key, b->key, a->key_len);
}

/** Finds the value r with brute force s.t. M=rG
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The resulting integer
 *  \param  M          EC_POINT object
 *  \return 1 on success and 0 otherwise
 */
static int EC_ELGAMAL_discrete_log_brute(EC_ELGAMAL_CTX *ctx, int32_t *r,
                                         EC_POINT *M)
{
    int ret = 0;
    int64_t i = 1, max = 1LL << EC_ELGAMAL_MAX_BITS;
    const EC_POINT *G;
    EC_POINT *P = NULL;
    BN_CTX *bn_ctx = NULL;

    if (EC_POINT_is_at_infinity(ctx->key->group, M))
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    P = EC_POINT_new(ctx->key->group);
    if (P == NULL)
        goto err;

    G = EC_GROUP_get0_generator(ctx->key->group);
    EC_POINT_set_to_infinity(ctx->key->group, P);

    for (; i < max; i++) {
        if (!EC_POINT_add(ctx->key->group, P, P, G, bn_ctx))
            goto err;
        if (EC_POINT_cmp(ctx->key->group, P, M, bn_ctx) == 0)
            break;
    }

    if (i >= max)
        goto err;

    *r = (int32_t)i;
    ret = 1;

err:
    EC_POINT_free(P);
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Finds the value r with ecdlp bsgs hashtable.
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The resulting integer
 *  \param  M          EC_POINT object
 *  \return 1 on success and 0 otherwise
 */
static int EC_ELGAMAL_discrete_log_bsgs(EC_ELGAMAL_CTX *ctx, int32_t *r,
                                        EC_POINT *M)
{
    int ret = 0;
    int64_t i, max;
    EC_POINT *P = NULL, *Q = NULL;
    const EC_POINT *G = NULL;
    EC_ELGAMAL_DECRYPT_TABLE *table = ctx->decrypt_table;
    EC_ELGAMAL_dec_tbl_entry *entry = NULL, *entry_res = NULL;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return ret;

    if (table->decrypt_negative == 1) {
        G = EC_GROUP_get0_generator(ctx->key->group);

        Q = EC_POINT_new(ctx->key->group);
        if (Q == NULL)
            goto err;

        EC_POINT_set_to_infinity(ctx->key->group, Q);

        P = EC_POINT_new(ctx->key->group);
        if (P == NULL)
            goto err;

        max = 1L << EC_ELGAMAL_ECDLP_BABY_BITS;
    } else {
        if ((P = EC_POINT_dup(M, ctx->key->group)) == NULL)
            goto err;
        max = (int64_t)table->size * (int64_t)table->size;
    }

    for (i = 0; i < max; i++) {
        if (table->decrypt_negative == 1) {
            if (!EC_POINT_add(ctx->key->group, Q, Q, G, bn_ctx))
                goto err;

            if (!EC_POINT_copy(P, Q))
                goto err;

            if (!EC_POINT_invert(ctx->key->group, P, bn_ctx))
                goto err;

            if (!EC_POINT_add(ctx->key->group, P, P, M, bn_ctx))
                goto err;
        }

        entry = EC_ELGAMAL_dec_tbl_entry_new(ctx, P, (int32_t)i);
        if (entry == NULL)
            goto err;

        entry_res = lh_EC_ELGAMAL_dec_tbl_entry_retrieve(table->entries, entry);
        if (entry_res != NULL) {
            ret = 1;
            if (table->decrypt_negative == 1)
                *r = (int32_t)(((entry_res->value & 0xffffffff) <<
                                            EC_ELGAMAL_ECDLP_BABY_BITS) + i + 1);
            else
                *r = (int32_t)(i * table->size + entry_res->value);
            break;
        }

        if (table->decrypt_negative != 1
            && !EC_POINT_add(ctx->key->group, P, P, table->mG_inv, bn_ctx))
            goto err;

        EC_ELGAMAL_dec_tbl_entry_free(entry);
        entry = NULL;
    }

err:
    BN_CTX_free(bn_ctx);
    EC_ELGAMAL_dec_tbl_entry_free(entry);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    return ret;
}

/** Creates a new EC_ELGAMAL_dec_tbl_entry object
 *  \param  ctx   EC_ELGAMAL_CTX object
 *  \param  point EC_POINT object
 *  \return newly created EC_ELGAMAL_dec_tbl_entry object or NULL in case of an error
 */
static EC_ELGAMAL_dec_tbl_entry *EC_ELGAMAL_dec_tbl_entry_new(EC_ELGAMAL_CTX *ctx,
                                                              EC_POINT *point,
                                                              int32_t value)
{
    EC_ELGAMAL_dec_tbl_entry *entry = NULL;
    size_t point_size = 0, len = 0;
    unsigned char *point_key = NULL;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    point_size = EC_POINT_point2oct(ctx->key->group, point,
                                    POINT_CONVERSION_COMPRESSED, NULL, 0,
                                    bn_ctx);
    if (point_size <= 0)
        goto err;

    entry = OPENSSL_zalloc(sizeof(*entry));
    if (entry == NULL)
        goto err;

    point_key = OPENSSL_zalloc(point_size + 1);
    if (point_key == NULL)
        goto err;

    if ((len = EC_POINT_point2oct(ctx->key->group, point,
                                  POINT_CONVERSION_COMPRESSED, point_key,
                                  point_size, bn_ctx)) != point_size)
        goto err;

    entry->key_len = (int)point_size;
    entry->key = point_key;
    entry->value = value;

    BN_CTX_free(bn_ctx);

    return entry;

err:
    OPENSSL_free(point_key);
    OPENSSL_free(entry);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_dec_tbl_entry object
 *  \param  entry  EC_ELGAMAL_dec_tbl_entry object to be freed
 */
static void EC_ELGAMAL_dec_tbl_entry_free(EC_ELGAMAL_dec_tbl_entry *entry)
{
    if (entry == NULL)
        return;

    OPENSSL_free(entry->key);
    OPENSSL_free(entry);
}

/** Creates a new EC_ELGAMAL_DECRYPT_TABLE object
 *  \param  ctx              EC_ELGAMAL_CTX object
 *  \param  decrypt_negative Whether negative numbers can be decrypted (1 or 0)
 *  \return newly created EC_ELGAMAL_DECRYPT_TABLE object or NULL in case of an error
 */
EC_ELGAMAL_DECRYPT_TABLE *EC_ELGAMAL_DECRYPT_TABLE_new(EC_ELGAMAL_CTX *ctx,
                                                       int32_t decrypt_negative)
{
    EC_ELGAMAL_DECRYPT_TABLE *table = NULL;
    EC_ELGAMAL_dec_tbl_entry *entry = NULL, *entry_old = NULL;
    LHASH_OF(EC_ELGAMAL_dec_tbl_entry) *entries = NULL;
    EC_GROUP *group;
    EC_POINT *P = NULL, *mG_inv = NULL;
    const EC_POINT *G;
    BIGNUM *bn_size = NULL;
    BN_CTX *bn_ctx = NULL;
    int32_t i, size = 1L << (EC_ELGAMAL_ECDLP_GIANT_BITS - 1);

    if (ctx == NULL || ctx->key == NULL)
        return NULL;

    group = ctx->key->group;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    table = OPENSSL_zalloc(sizeof(*table));
    if (table == NULL)
        goto err;

    table->size = size;

    bn_size = BN_CTX_get(bn_ctx);
    if (bn_size == NULL)
        goto err;
    BN_set_word(bn_size,  (BN_ULONG)size);
    BN_set_negative(bn_size, 0);

    G = EC_GROUP_get0_generator(group);

    mG_inv = EC_POINT_new(group);
    if (mG_inv == NULL)
        goto err;

    if (!EC_POINT_mul(group, mG_inv, bn_size, NULL, NULL, bn_ctx))
        goto err;

    if (!EC_POINT_invert(group, mG_inv, bn_ctx))
        goto err;

    table->mG_inv = mG_inv;

    entries = lh_EC_ELGAMAL_dec_tbl_entry_new(EC_ELGAMAL_dec_tbl_entry_hash,
                                              EC_ELGAMAL_dec_tbl_entry_cmp);
    if (entries == NULL)
        goto err;

    P = EC_POINT_new(ctx->key->group);
    if (P == NULL)
        goto err;

    if (decrypt_negative != 1)
        EC_POINT_set_to_infinity(group, P);

    for (i = decrypt_negative == 1 ? -size : 0; i < size; i++) {
        if (decrypt_negative == 1) {
            BN_set_word(bn_size, (BN_ULONG)((int64_t)i < 0 ? -i : i)
                                                << EC_ELGAMAL_ECDLP_BABY_BITS);
            if (!EC_POINT_mul(group, P, bn_size, NULL, NULL, bn_ctx))
                goto err;
            if (i < 0) {
                if (!EC_POINT_invert(group, P, bn_ctx))
                    goto err;
            }
        }

        entry = EC_ELGAMAL_dec_tbl_entry_new(ctx, P, i);
        if (entry == NULL)
            goto err;

        entry_old = lh_EC_ELGAMAL_dec_tbl_entry_insert(entries, entry);
        if (lh_EC_ELGAMAL_dec_tbl_entry_error(entries) && entry_old == NULL)
            goto err;

        if (entry_old != NULL)
            EC_ELGAMAL_dec_tbl_entry_free(entry_old);

        entry = NULL;

        if (decrypt_negative != 1 && !EC_POINT_add(group, P, P, G, bn_ctx))
            goto err;
    }

    table->entries = entries;
    table->decrypt_negative = decrypt_negative;

    table->references = 1;
    table->lock = CRYPTO_THREAD_lock_new();

    EC_POINT_free(P);
    BN_CTX_free(bn_ctx);

    return table;

err:
    EC_ELGAMAL_dec_tbl_entry_free(entry);
    lh_EC_ELGAMAL_dec_tbl_entry_doall(entries, EC_ELGAMAL_dec_tbl_entry_free);
    lh_EC_ELGAMAL_dec_tbl_entry_free(entries);
    EC_POINT_free(P);
    EC_POINT_free(mG_inv);
    OPENSSL_free(table);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_DECRYPT_TABLE object
 *  \param  table  EC_ELGAMAL_DECRYPT_TABLE object to be freed
 */
void EC_ELGAMAL_DECRYPT_TABLE_free(EC_ELGAMAL_DECRYPT_TABLE *table)
{
    int i;

    if (table == NULL)
        return;

    CRYPTO_DOWN_REF(&table->references, &i, table->lock);

    if (i > 0)
        return;

    lh_EC_ELGAMAL_dec_tbl_entry_doall(table->entries, EC_ELGAMAL_dec_tbl_entry_free);

    lh_EC_ELGAMAL_dec_tbl_entry_free(table->entries);
    EC_POINT_free(table->mG_inv);
    CRYPTO_THREAD_lock_free(table->lock);
    OPENSSL_free(table);
}

/** Sets a EC_ELGAMAL_DECRYPT_TABLE object for decryption.
 *  \param  ctx   EC_ELGAMAL_CTX object
 *  \param  table EC_ELGAMAL_DECRYPT_TABLE object
 */
void EC_ELGAMAL_CTX_set_decrypt_table(EC_ELGAMAL_CTX *ctx,
                                      EC_ELGAMAL_DECRYPT_TABLE *table)
{
    int i;

    ctx->decrypt_table = table;
    CRYPTO_UP_REF(&table->references, &i, table->lock);
}

/** Creates a new EC_ELGAMAL object
 *  \param  key  EC_KEY to use
 *  \return newly created EC_ELGAMAL_CTX object or NULL in case of an error
 */
EC_ELGAMAL_CTX *EC_ELGAMAL_CTX_new(EC_KEY *key)
{
    EC_ELGAMAL_CTX *ctx = NULL;

    if (key == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        goto err;

    EC_KEY_up_ref(key);
    ctx->key = key;

    return ctx;

err:
    OPENSSL_free(ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_CTX object
 *  \param  ctx  EC_ELGAMAL_CTX object to be freed
 */
void EC_ELGAMAL_CTX_free(EC_ELGAMAL_CTX *ctx)
{
    if (ctx == NULL)
        return;

    EC_KEY_free(ctx->key);
    EC_ELGAMAL_DECRYPT_TABLE_free(ctx->decrypt_table);
    OPENSSL_free(ctx);
}

/** Creates a new EC_ELGAMAL_CIPHERTEXT object for EC-ELGAMAL oparations
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \return newly created EC_ELGAMAL_CIPHERTEXT object or NULL in case of an error
 */
EC_ELGAMAL_CIPHERTEXT *EC_ELGAMAL_CIPHERTEXT_new(EC_ELGAMAL_CTX *ctx)
{
    EC_POINT *C1 = NULL, *C2 = NULL;
    EC_ELGAMAL_CIPHERTEXT *ciphertext;

    ciphertext = OPENSSL_zalloc(sizeof(*ciphertext));
    if (ciphertext == NULL)
        return NULL;

    C1 = EC_POINT_new(ctx->key->group);
    if (C1 == NULL)
        goto err;

    C2 = EC_POINT_new(ctx->key->group);
    if (C2 == NULL)
        goto err;

    ciphertext->C1 = C1;
    ciphertext->C2 = C2;

    return ciphertext;

err:
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    OPENSSL_free(ciphertext);
    return NULL;
}

/** Frees a EC_ELGAMAL_CIPHERTEXT object
 *  \param  ciphertext  EC_ELGAMAL_CIPHERTEXT object to be freed
 */
void EC_ELGAMAL_CIPHERTEXT_free(EC_ELGAMAL_CIPHERTEXT *ciphertext)
{
    if (ciphertext == NULL)
        return;

    EC_POINT_free(ciphertext->C1);
    EC_POINT_free(ciphertext->C2);

    OPENSSL_free(ciphertext);
}

/** Encodes EC_ELGAMAL_CIPHERTEXT to binary
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  ciphertext EC_ELGAMAL_CIPHERTEXT object
 *  \param  compressed Whether to compress the encoding (either 0 or 1)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t EC_ELGAMAL_CIPHERTEXT_encode(EC_ELGAMAL_CTX *ctx, unsigned char *out,
                                    size_t size, EC_ELGAMAL_CIPHERTEXT *ciphertext,
                                    int compressed)
{
    size_t point_len, ret = 0, len;
    unsigned char *p = out;
    point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED :
                                                POINT_CONVERSION_UNCOMPRESSED;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto end;

    point_len = EC_POINT_point2oct(ctx->key->group,
                                   EC_GROUP_get0_generator(ctx->key->group),
                                   form, NULL, 0, bn_ctx);
    len = point_len * 2;
    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    if (ciphertext == NULL || ciphertext->C1 == NULL || ciphertext->C2 == NULL)
        goto end;

    if (EC_POINT_point2oct(ctx->key->group, ciphertext->C1, form, p, point_len,
                           bn_ctx) != point_len)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(ctx->key->group, ciphertext->C2, form, p, point_len,
                           bn_ctx) != point_len)
        goto end;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Decodes binary to EC_ELGAMAL_CIPHERTEXT
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          the resulting ciphertext
 *  \param  in         Memory buffer with the encoded EC_ELGAMAL_CIPHERTEXT
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_CIPHERTEXT_decode(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                                 unsigned char *in, size_t size)
{
    int ret = 0;
    size_t point_len;
    unsigned char *p = in;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || r->C1 == NULL ||
        r->C2 == NULL || size % 2 != 0)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    point_len = EC_POINT_point2oct(ctx->key->group,
                                   EC_GROUP_get0_generator(ctx->key->group),
                                   POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
    if (size < (point_len * 2))
        goto err;

    point_len = size / 2;

    if (!EC_POINT_oct2point(ctx->key->group, r->C1, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(ctx->key->group, r->C2, p, point_len, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Encrypts an Integer with additadive homomorphic EC-ElGamal
 *  \param  ctx        EC_ELGAMAL_CTX object.
 *  \param  r          EC_ELGAMAL_CIPHERTEXT object that stores the result of
 *                     the encryption
 *  \param  plaintext  The plaintext integer to be encrypted
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_encrypt(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r, int32_t plaintext)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_plain = NULL, *ord = NULL, *rand = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->pub_key == NULL || r == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    bn_plain = BN_CTX_get(bn_ctx);
    ord = BN_CTX_get(bn_ctx);
    rand = BN_CTX_get(bn_ctx);
    if (rand == NULL)
        goto err;

    if (r->C1 == NULL) {
        r->C1 = EC_POINT_new(ctx->key->group);
        if (r->C1 == NULL)
            goto err;
    }

    if (r->C2 == NULL) {
        r->C2 = EC_POINT_new(ctx->key->group);
        if (r->C2 == NULL)
            goto err;
    }

    EC_GROUP_get_order(ctx->key->group, ord, bn_ctx);
    BN_rand_range(rand, ord);

    BN_set_word(bn_plain, plaintext);

    if (!EC_POINT_mul(ctx->key->group, r->C1, rand, NULL, NULL, bn_ctx))
        goto err;

    if (!EC_POINT_mul(ctx->key->group, r->C2, bn_plain, ctx->key->pub_key,
                      rand, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);

    if (!ret) {
        EC_POINT_free(r->C1);
        EC_POINT_free(r->C2);
        r->C1 = NULL;
        r->C2 = NULL;
    }

    return ret;
}

/** Decrypts the ciphertext
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The resulting plaintext integer
 *  \param  cihpertext EC_ELGAMAL_CIPHERTEXT object to be decrypted
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_decrypt(EC_ELGAMAL_CTX *ctx, int32_t *r, EC_ELGAMAL_CIPHERTEXT *ciphertext)
{
    int ret = 0;
    int32_t plaintext = 0;
    EC_POINT *M = NULL;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->priv_key == NULL || r == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    M = EC_POINT_new(ctx->key->group);
    if (M == NULL)
        goto err;

    if (!EC_POINT_mul(ctx->key->group, M, NULL, ciphertext->C1,
                      ctx->key->priv_key, bn_ctx))
        goto err;

    if (!EC_POINT_invert(ctx->key->group, M, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, M, ciphertext->C2, M, bn_ctx))
        goto err;

    if (ctx->decrypt_table != NULL) {
        if (!EC_ELGAMAL_discrete_log_bsgs(ctx, &plaintext, M))
            goto err;
    } else {
        if (!EC_ELGAMAL_discrete_log_brute(ctx, &plaintext, M))
            goto err;
    }

    *r = plaintext;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    EC_POINT_free(M);
    return ret;
}

/** Adds two EC-Elgamal ciphertext and stores it in r (r = c1 + c2).
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The EC_ELGAMAL_CIPHERTEXT object that stores the addition
 *                     result
 *  \param  c1         EC_ELGAMAL_CIPHERTEXT object
 *  \param  c2         EC_ELGAMAL_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_add(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                   EC_ELGAMAL_CIPHERTEXT *c1, EC_ELGAMAL_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c1 == NULL || c2 == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C1, c1->C1, c2->C1, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C2, c1->C2, c2->C2, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Substracts two EC-Elgamal ciphertext and stores it in r (r = c1 - c2).
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The EC_ELGAMAL_CIPHERTEXT object that stores the
 *                     subtraction result
 *  \param  c1         EC_ELGAMAL_CIPHERTEXT object
 *  \param  c2         EC_ELGAMAL_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_sub(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                   EC_ELGAMAL_CIPHERTEXT *c1, EC_ELGAMAL_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *C1_inv = NULL, *C2_inv = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c1 == NULL || c2 == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    if ((C1_inv = EC_POINT_dup(c2->C1, ctx->key->group)) == NULL)
        goto err;

    if ((C2_inv = EC_POINT_dup(c2->C2, ctx->key->group)) == NULL)
        goto err;

    if (!EC_POINT_invert(ctx->key->group, C1_inv, bn_ctx))
        goto err;

    if (!EC_POINT_invert(ctx->key->group, C2_inv, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C1, c1->C1, C1_inv, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C2, c1->C2, C2_inv, bn_ctx))
        goto err;

    ret = 1;

err:
    EC_POINT_free(C1_inv);
    EC_POINT_free(C2_inv);
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Ciphertext multiplication, computes r = c * m
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The EC_ELGAMAL_CIPHERTEXT object that stores the
 *                     multiplication result
 *  \param  c1         EC_ELGAMAL_CIPHERTEXT object
 *  \param  c2         EC_ELGAMAL_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_mul(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                   EC_ELGAMAL_CIPHERTEXT *c, int32_t m)
{
    int ret = 0;
    BIGNUM *bn_m;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    bn_m = BN_CTX_get(bn_ctx);
    if (bn_m == NULL)
        goto err;
    BN_set_word(bn_m, (BN_ULONG)(m > 0 ? m : -m));
    BN_set_negative(bn_m, m < 0 ? 1 : 0);

    if (!EC_POINT_mul(ctx->key->group, r->C1, NULL, c->C1, bn_m, bn_ctx))
        goto err;

    if (!EC_POINT_mul(ctx->key->group, r->C2, NULL, c->C2, bn_m, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}
