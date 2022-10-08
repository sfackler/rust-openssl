/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#include <stdio.h>
#include <openssl/opensslconf.h>
#include "ssl_local_ntls.h"
#include "statem_local_ntls.h"
#include "internal/constant_time.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#ifndef OPENSSL_NO_NTLS
static int ntls_construct_ske_sm2dhe(SSL *s, WPACKET *pkt)
{
# if !defined(OPENSSL_NO_SM2) && !defined(OPENSSL_NO_SM3)
    int ret = 0;
    X509 *x509;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *encodedPoint = NULL;
    int encodedlen;
    EVP_MD_CTX *md_ctx = NULL;
    char *id = "1234567812345678";
    size_t siglen;
    size_t paramlen, paramoffset;
    unsigned char *sigbytes1, *sigbytes2;
    int curve_id;

    if (!WPACKET_get_total_written(pkt, &paramoffset)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* get signing cert and pkey */
    if (!(x509 = s->cert->pkeys[SSL_PKEY_SM2_SIGN].x509)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pkey = s->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey;
    if (pkey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* check tmp pkey not set */
    if (s->s3->tmp.pkey != NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    curve_id = tls1_shared_group(s, -2);

    if (!WPACKET_put_bytes_u8(pkt, NAMED_CURVE_TYPE)
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_put_bytes_u8(pkt, curve_id)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* generate tmp pkey and output ECPoint */
    /* FIXME: curveid is fixed to 31
    if (!(curve_id = tls1_ec_nid2curve_id(NID_sm2p256v1)))
        return 0;
    */
    s->s3->tmp.pkey = ssl_generate_pkey_group(s, curve_id);
    /* Generate a new key for this curve */
    if (s->s3->tmp.pkey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Encode the public key. */
    encodedlen = EVP_PKEY_get1_tls_encodedpoint(s->s3->tmp.pkey,
                                                &encodedPoint);
    if (encodedlen == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto err;
    }

    if (!WPACKET_sub_memcpy_u8(pkt, encodedPoint, encodedlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!WPACKET_get_length(pkt, &paramlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!(md_ctx = EVP_MD_CTX_new())) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto err;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_CTX_set1_id(pctx, id, strlen(id)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto err;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pctx);;

    /* sign digest of {client_random, server_random, sm2dhe_params} */
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_DigestSignUpdate(md_ctx, &(s->s3->client_random[0]),
                             SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestSignUpdate(md_ctx, &(s->s3->server_random[0]),
                                    SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestSignUpdate(md_ctx, s->init_buf->data + paramoffset,
                                    paramlen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto err;
    }

    if ((siglen = EVP_PKEY_size(pkey)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto err;
    }

    if (!WPACKET_sub_reserve_bytes_u16(pkt, siglen, &sigbytes1)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (EVP_DigestSignFinal(md_ctx, sigbytes1, (size_t *)&siglen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto err;
    }

    if (!WPACKET_sub_allocate_bytes_u16(pkt, siglen, &sigbytes2)
            || sigbytes1 != sigbytes2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = 1;

 err:
    if (!ret && s->s3->tmp.pkey) {
        EVP_PKEY_free(s->s3->tmp.pkey);
        s->s3->tmp.pkey = NULL;
    }
    OPENSSL_free(encodedPoint);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pctx);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2DHE,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int ntls_construct_ske_sm2(SSL *s, WPACKET *pkt)
{
# if !defined(OPENSSL_NO_SM2) && !defined(OPENSSL_NO_SM3)
    int ret = 0, n;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509 *x509;
    unsigned char *buf = NULL, *p = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    char *id = "1234567812345678";
    size_t siglen;
    unsigned char *sigbytes1, *sigbytes2;

    pkey = s->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey;
    /* prepare sign key */
    if (pkey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* prepare encrypt cert buffer */
    if (!(x509 = s->cert->pkeys[SSL_PKEY_SM2_ENC].x509)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((n = i2d_X509(x509, NULL)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * XXX: This is very stupid since the standard doesn't mention the
     * 3 bytes for length
     */
    buf = OPENSSL_malloc(n + 3);
    if (buf == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }

    p = buf;
    l2n3(n, p);

    if ((n = i2d_X509(x509, &p)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    n += 3;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_MALLOC_FAILURE);
        goto end;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (EVP_PKEY_CTX_set1_id(pctx, id, strlen(id)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pctx);

    /* generate signature */
    if ((siglen = EVP_PKEY_size(pkey)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (!WPACKET_sub_reserve_bytes_u16(pkt, siglen, &sigbytes1)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    /* sign digest of {client_random, server_random, enc_cert} */
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestSignUpdate(md_ctx, &(s->s3->client_random[0]),
                                SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestSignUpdate(md_ctx, &(s->s3->server_random[0]),
                                    SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestSignUpdate(md_ctx, buf, n) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestSignFinal(md_ctx, sigbytes1, &siglen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (!WPACKET_sub_allocate_bytes_u16(pkt, siglen, &sigbytes2)
            || sigbytes1 != sigbytes2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    ret = 1;

 end:
    OPENSSL_free(buf);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pctx);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_SM2,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int ntls_construct_ske_rsa(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_RSA
    int ret = 0;
    EVP_PKEY *pkey;
    X509 *x509;
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *buf = NULL, *p = NULL;
    int n;
    size_t siglen;
    unsigned char *sigbytes1, *sigbytes2;
    const SIGALG_LOOKUP *lu = s->s3->tmp.sigalg;

    /* get sign pkey */
    if (!(pkey = s->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tls1_lookup_md(lu, &md)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* get enc cert */
    if (!(x509 = s->cert->pkeys[SSL_PKEY_RSA_ENC].x509)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((n = i2d_X509(x509, NULL)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* XXX: Should the heading 3 bytes be necessary? */
    buf = OPENSSL_malloc(n + 3);
    if (buf == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }

    p = &(buf[3]);

    if ((n = i2d_X509(x509, &p)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    l2n3(n, buf);
    buf -= 3;

    siglen = EVP_PKEY_size(pkey);

    if (!WPACKET_sub_reserve_bytes_u16(pkt, siglen, &sigbytes1)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    /* generate signature */
    if (!(md_ctx = EVP_MD_CTX_new())) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_MALLOC_FAILURE);
        goto end;
    }

    /* sign digest of {client_random, server_random, enc_cert} */
    if (EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestSignUpdate(md_ctx, &(s->s3->client_random[0]),
                             SSL3_RANDOM_SIZE) <= 0
        || EVP_DigestSignUpdate(md_ctx, &(s->s3->server_random[0]),
                                SSL3_RANDOM_SIZE) <= 0
        || EVP_DigestSignUpdate(md_ctx, buf, n) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestSignFinal(md_ctx, sigbytes1, &siglen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (!WPACKET_sub_allocate_bytes_u16(pkt, siglen, &sigbytes2)
            || sigbytes1 != sigbytes2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    ret = 1;
 end:
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(buf);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_SKE_RSA,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

int ntls_construct_server_key_exchange_ntls(SSL *s, WPACKET *pkt)
{
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    if (alg_k & SSL_kSM2) {
        if (!ntls_construct_ske_sm2(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kSM2DHE) {
        if (!ntls_construct_ske_sm2dhe(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kRSA) {
        if (!ntls_construct_ske_rsa(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                      SSL_F_NTLS_CONSTRUCT_SERVER_KEY_EXCHANGE_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return 1;

 err:
    return 0;
}

static int ntls_process_cke_sm2dhe(SSL *s, PACKET *pkt)
{
# if !defined(OPENSSL_NO_SM2) && !defined(OPENSSL_NO_SM3)
    int ret = 0;
    const unsigned char *ecparams;
    PACKET encoded_pt;
    EVP_PKEY *skey = s->s3->tmp.pkey;
    EVP_PKEY *ckey = NULL;

    if ((skey = s->s3->tmp.pkey) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_bytes(pkt, &ecparams, 3)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                      SSL_R_LENGTH_TOO_SHORT);
        return 0;
    }

    /* parse ECPoint */
    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                      SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (!(ckey = EVP_PKEY_new())) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (EVP_PKEY_copy_parameters(ckey, skey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (!EVP_PKEY_set1_tls_encodedpoint(ckey, PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                      SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (!ntls_sm2_derive_ntls(s, skey, ckey)) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                      SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    ret = 1;

 end:
    EVP_PKEY_free(s->s3->tmp.pkey);
    s->s3->tmp.pkey = NULL;
    EVP_PKEY_free(ckey);

    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_NTLS_PROCESS_CKE_SM2DHE,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int ntls_process_cke_sm2(SSL *s, PACKET *pkt)
{
# ifndef OPENSSL_NO_SM2
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    PACKET enced_pms;
    EVP_PKEY_CTX *pctx = NULL;
    size_t pmslen;
    unsigned char pms[SSL_MAX_MASTER_KEY_LENGTH];

    pkey = s->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey;
    /* prepare decryption key */
    if (pkey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                      SSL_R_MISSING_SM2_ENC_CERTIFICATE);
        return 0;
    }

    /* set pkey to SM2 */
    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    /*
     * XXX:
     * This is very unclear. The standard TLS protocol requries no u16 len
     * bytes before the encrypted PMS value. The NTLS specification is also
     * very blurry on this. But major implementations require the 2 bytes
     * length field (which is redundant), otherwise handshake will fail...
     */
    /* parse encrypted pre_master_secret */
    if (!PACKET_get_length_prefixed_2(pkt, &enced_pms)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                      SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    /* decrypt encrypted pre_master_secret */
    if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!EVP_PKEY_decrypt_init(pctx)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    pmslen = sizeof(pms);

    if (!EVP_PKEY_decrypt(pctx, pms, &pmslen,
                          PACKET_data(&enced_pms),
                          PACKET_remaining(&enced_pms))) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                      SSL_R_DECRYPTION_FAILED);
        goto end;
    }

    if (pmslen != SSL_MAX_MASTER_KEY_LENGTH) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                      SSL_R_DECRYPTION_FAILED);
        goto end;
    }

    /* XXX: don't care about versions in PMS */

    /* generate master_secret */
    if (!ssl_generate_master_secret(s, pms, pmslen, 0)) {
        /* SSLfatal_ntls already called */
        goto end;
    }

    ret = 1;
 end:
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_cleanse(pms, sizeof(pms));

    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_CKE_SM2,
                  SSL_R_DECRYPTION_FAILED);
    return 0;
# endif
}

static int ntls_process_cke_rsa(SSL *s, PACKET *pkt)
{
#ifndef OPENSSL_NO_RSA
    unsigned char rand_premaster_secret[SSL_MAX_MASTER_KEY_LENGTH];
    int decrypt_len;
    unsigned char decrypt_good, version_good;
    size_t j, padding_len;
    PACKET enc_premaster;
    RSA *rsa = NULL;
    unsigned char *rsa_decrypt = NULL;
    int ret = 0;
# ifndef OPENSSL_NO_STATUS
    /* record encrypted client pms with RSA KeyExchange mode */
    unsigned char *p;
    size_t n;
# endif

    if (!PACKET_get_length_prefixed_2(pkt, &enc_premaster)
        || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                      SSL_R_LENGTH_MISMATCH);
        return 0;
    }

# ifndef OPENSSL_NO_STATUS
    /* record encrypted client pms with RSA KeyExchange mode */
    p = (unsigned char *)enc_premaster.curr;
    n = enc_premaster.remaining;
    if (s->status_param.ssl_status_enable) {
        s->status_param.type = SSL_CLIENT_RSA_EXCHANGE;
        if (s->status_callback(p, n, &s->status_param) == -1) {
            /* TODO: debug info */
            return 0;
        }
    }
# endif

    rsa = EVP_PKEY_get0_RSA(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey);
    if (rsa == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                      SSL_R_MISSING_RSA_ENCRYPTING_CERT);
        return 0;
    }
    /*
     * We want to be sure that the plaintext buffer size makes it safe to
     * iterate over the entire size of a premaster secret
     * (SSL_MAX_MASTER_KEY_LENGTH). Reject overly short RSA keys because
     * their ciphertext cannot accommodate a premaster secret anyway.
     */
    if (RSA_size(rsa) < SSL_MAX_MASTER_KEY_LENGTH) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                      RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    rsa_decrypt = OPENSSL_malloc(RSA_size(rsa));
    if (rsa_decrypt == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * We must not leak whether a decryption failure occurs because of
     * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
     * section 7.4.7.1). The code follows that advice of the TLS RFC and
     * generates a random premaster secret for the case that the decrypt
     * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
     */

    if (RAND_priv_bytes(rand_premaster_secret,
                        sizeof(rand_premaster_secret)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    {
        /*
         * Decrypt with no padding. PKCS#1 padding will be removed as part of
         * the timing-sensitive code below.
         */
        /* TODO(size_t): Convert this function */
        decrypt_len = (int)RSA_private_decrypt((int)PACKET_remaining(&enc_premaster),
                                               PACKET_data(&enc_premaster),
                                               rsa_decrypt, rsa, RSA_NO_PADDING);

        if (decrypt_len < 0) {
            SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                          ERR_R_INTERNAL_ERROR);
            goto err;
        }

        /* Check the padding. See RFC 3447, section 7.2.2. */

        /*
         * The smallest padded premaster is 11 bytes of overhead. Small keys
         * are publicly invalid, so this may return immediately. This ensures
         * PS is at least 8 bytes.
         */
        if (decrypt_len < 11 + SSL_MAX_MASTER_KEY_LENGTH) {
            SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                          SSL_R_DECRYPTION_FAILED);
            goto err;
        }

        padding_len = decrypt_len - SSL_MAX_MASTER_KEY_LENGTH;
        decrypt_good = constant_time_eq_int_8(rsa_decrypt[0], 0) &
                       constant_time_eq_int_8(rsa_decrypt[1], 2);
        for (j = 2; j < padding_len - 1; j++) {
            decrypt_good &= ~constant_time_is_zero_8(rsa_decrypt[j]);
        }
        decrypt_good &= constant_time_is_zero_8(rsa_decrypt[padding_len - 1]);
    }

    /*
     * If the version in the decrypted pre-master secret is correct then
     * version_good will be 0xff, otherwise it'll be zero. The
     * Klima-Pokorny-Rosa extension of Bleichenbacher's attack
     * (http://eprint.iacr.org/2003/052/) exploits the version number
     * check as a "bad version oracle". Thus version checks are done in
     * constant time and are treated like any other decryption error.
     */
    version_good =
        constant_time_eq_8(rsa_decrypt[padding_len],
                           (unsigned)(s->client_version >> 8));
    version_good &=
        constant_time_eq_8(rsa_decrypt[padding_len + 1],
                           (unsigned)(s->client_version & 0xff));

    /*
     * The premaster secret must contain the same version number as the
     * ClientHello to detect version rollback attacks (strangely, the
     * protocol does not offer such protection for DH ciphersuites).
     * However, buggy clients exist that send the negotiated protocol
     * version instead if the server does not support the requested
     * protocol version. If SSL_OP_TLS_ROLLBACK_BUG is set, tolerate such
     * clients.
     */
    if (s->options & SSL_OP_TLS_ROLLBACK_BUG) {
        unsigned char workaround_good;
        workaround_good = constant_time_eq_8(rsa_decrypt[padding_len],
                                             (unsigned)(s->version >> 8));
        workaround_good &=
            constant_time_eq_8(rsa_decrypt[padding_len + 1],
                               (unsigned)(s->version & 0xff));
        version_good |= workaround_good;
    }

    /*
     * Both decryption and version must be good for decrypt_good to
     * remain non-zero (0xff).
     */
    decrypt_good &= version_good;

    /*
     * Now copy rand_premaster_secret over from p using
     * decrypt_good_mask. If decryption failed, then p does not
     * contain valid plaintext, however, a check above guarantees
     * it is still sufficiently large to read from.
     */
    for (j = 0; j < sizeof(rand_premaster_secret); j++) {
        rsa_decrypt[padding_len + j] =
            constant_time_select_8(decrypt_good,
                                   rsa_decrypt[padding_len + j],
                                   rand_premaster_secret[j]);
    }

    if (!ssl_generate_master_secret(s, rsa_decrypt + padding_len,
                                    sizeof(rand_premaster_secret), 0)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    ret = 1;
err:
    OPENSSL_free(rsa_decrypt);
    return ret;
#else
    /* Should never happen */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_CKE_RSA,
                  ERR_R_INTERNAL_ERROR);
    return 0;
#endif
}

MSG_PROCESS_RETURN ntls_process_client_key_exchange_ntls(SSL *s, PACKET *pkt)
{
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    if (alg_k & SSL_kRSA) {
        if (!ntls_process_cke_rsa(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kSM2) {
        if (!ntls_process_cke_sm2(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kSM2DHE) {
        if (!ntls_process_cke_sm2dhe(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                      SSL_F_NTLS_PROCESS_CLIENT_KEY_EXCHANGE_NTLS,
                      SSL_R_UNKNOWN_CIPHER_TYPE);
        goto err;
    }

    return MSG_PROCESS_CONTINUE_PROCESSING;

 err:
    return MSG_PROCESS_ERROR;
}

MSG_PROCESS_RETURN ntls_process_cert_verify_ntls(SSL *s, PACKET *pkt)
{
    MSG_PROCESS_RETURN ret = MSG_PROCESS_ERROR;
    EVP_PKEY *pkey = NULL;
    const unsigned char *data;
    unsigned int len;
    X509 *peer;
    const EVP_MD *md = NULL;
    size_t hdatalen = 0;
    void *hdata;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_MD_CTX *mctx2 = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int j;
    unsigned char out[EVP_MAX_MD_SIZE];
    size_t outlen = 0;

    if (mctx == NULL || mctx2 == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * XXX: Don't forget that session->peer stores the client signing
     * certificate...
     */
    peer = s->session->peer;
    pkey = X509_get0_pubkey(peer);
    if (pkey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (ssl_cert_lookup_by_pkey(pkey, NULL) == NULL) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
        goto err;
    }

    if (!tls1_set_peer_legacy_sigalg(s, pkey)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!tls1_lookup_md(s->s3->tmp.peer_sigalg, &md)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!PACKET_get_net_2(pkt, &len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    j = EVP_PKEY_size(pkey);
    if (((int)len > j) || ((int)PACKET_remaining(pkt) > j)
        || (PACKET_remaining(pkt) == 0)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      SSL_R_WRONG_SIGNATURE_SIZE);
        goto err;
    }

    if (!PACKET_get_bytes(pkt, &data, len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
    if (hdatalen <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!EVP_DigestInit_ex(mctx2, md, NULL)
        || !EVP_DigestUpdate(mctx2, hdata, hdatalen)
        || !EVP_DigestFinal(mctx2, out, (unsigned int *)&outlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      ERR_R_EVP_LIB);
        goto err;
    }

#ifdef SSL_DEBUG
    fprintf(stderr, "Using client verify alg %s\n", EVP_MD_name(md));
    fprintf(stderr, "EVP_PKEY type: %s\n", OBJ_nid2ln(EVP_PKEY_id(pkey)));
#endif
#ifndef OPENSSL_NO_SM2
    if (EVP_PKEY_is_sm2(pkey)) {
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (pctx == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                          SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                          ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (EVP_PKEY_CTX_set1_id(pctx, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LEN) <= 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                          SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                          ERR_R_EVP_LIB);
            goto err;
        }

        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    }
#endif
    if (EVP_DigestVerifyInit(mctx, NULL, md, NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      ERR_R_EVP_LIB);
        goto err;
    }

    j = EVP_DigestVerify(mctx, data, len, out, outlen);
    if (j <= 0) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR,
                      SSL_F_NTLS_PROCESS_CERT_VERIFY_NTLS,
                      SSL_R_BAD_SIGNATURE);
        goto err;
    }

    ret = MSG_PROCESS_CONTINUE_READING;

 err:
    BIO_free(s->s3->handshake_buffer);
    s->s3->handshake_buffer = NULL;
    EVP_MD_CTX_free(mctx2);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

#endif
