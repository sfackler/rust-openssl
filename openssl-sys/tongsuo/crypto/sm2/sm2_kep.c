/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#include "internal/cryptlib.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "crypto/sm2.h"
#include "crypto/ec.h" /* ecdh_KDF_X9_63() */
#include "crypto/sm2err.h"


#ifndef OPENSSL_NO_SM2
int SM2_compute_key(void *out, size_t outlen, int server,
                    const char *peer_uid, int peer_uid_len,
                    const char *self_uid, int self_uid_len,
                    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key,
                    const EC_KEY *peer_pub_key, const EC_KEY *self_eckey,
                    const EVP_MD *md)
{
    BN_CTX *ctx = NULL;
    EC_POINT *UorV = NULL;
    const EC_POINT *Rs, *Rp;
    BIGNUM *Xs = NULL, *Xp = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key, *r;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;
    size_t elemet_len, idx;

    if (outlen > INT_MAX) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (peer_pub_key == NULL || self_eckey == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(self_eckey);
    if (priv_key == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }

    if (peer_ecdhe_key == NULL || self_ecdhe_key == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    Rs = EC_KEY_get0_public_key(self_ecdhe_key);
    Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
    r = EC_KEY_get0_private_key(self_ecdhe_key);

    if (Rs == NULL || Rp == NULL || r == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    Xs = BN_CTX_get(ctx);
    Xp = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    two_power_w = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);

    if (order == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    group = EC_KEY_get0_group(self_eckey);

    if (!EC_GROUP_get_order(group, order, ctx)
            || !EC_GROUP_get_cofactor(group, h, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    UorV = EC_POINT_new(group);
    if (UorV == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*Test peer public key On curve*/
    if (!EC_POINT_is_on_curve(group, Rp, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Get x*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
            == NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx)) {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx)) {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV,
                      EC_KEY_get0_public_key(peer_pub_key), ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    if (EC_POINT_is_at_infinity(group, UorV)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/

    elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
    buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
    buf = (unsigned char *)OPENSSL_zalloc(buflen + 10);
    if (buf == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
    idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
    if (!idx) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    len = EVP_MD_size(md);

    /* Z_A || Z_B, server is initiator(Z_A), client is responder(Z_B) */
    if (server) {
        if (!sm2_compute_z_digest((uint8_t *)(buf + idx), md,
                                  (const uint8_t *)self_uid,
                                  self_uid_len, self_eckey)) {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        idx += len;
    }

    if (!sm2_compute_z_digest((uint8_t *)(buf + idx), md,
                              (const uint8_t *)peer_uid, peer_uid_len,
                              peer_pub_key)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    idx += len;

    if (!server) {
        if (!sm2_compute_z_digest((uint8_t *)(buf + idx), md,
                                  (const uint8_t *)self_uid,
                                  self_uid_len, self_eckey)) {
            SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        idx += len;
    }

    if (!ecdh_KDF_X9_63(out, outlen, (const unsigned char *)(buf + 1), idx - 1,
                        NULL, 0, md)) {
        SM2err(SM2_F_SM2_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = outlen;

 err:
    EC_POINT_free(UorV);
    OPENSSL_free(buf);
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

#endif
