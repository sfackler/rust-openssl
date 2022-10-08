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

#ifndef OPENSSL_NO_NTLS
static int ntls_process_ske_sm2dhe(SSL *s, PACKET *pkt)
{
# if !defined(OPENSSL_NO_SM2) && !defined(OPENSSL_NO_SM3)
    int ret = 0;
    const unsigned char *ecparams;
    PACKET encoded_pt;
    EVP_PKEY_CTX *pctx = NULL;
    int paramslen;
    PACKET signature;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *mpctx = NULL;
    int maxsig;
    char *id = "1234567812345678";
    EVP_MD_CTX *md_ctx = NULL;

    /* parse ECParameter */
    if (!PACKET_get_bytes(pkt, &ecparams, 3)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      SSL_R_LENGTH_TOO_SHORT);
        return 0;
    }

    /* parse ECPoint */
    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2) <= 0
            || EVP_PKEY_paramgen(pctx, &s->s3->peer_tmp) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (s->s3->peer_tmp == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
                                        PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      SSL_R_BAD_ECPOINT);
        goto end;
    }

    /* get ECDHEParams length */
    paramslen = PACKET_data(pkt) - ecparams;

    /* parse signature packet, check no data remaining */
    if (!PACKET_get_length_prefixed_2(pkt, &signature)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      SSL_R_LENGTH_MISMATCH);
        goto end;
    }

    if ((pkey = X509_get0_pubkey(s->session->peer)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if ((maxsig = EVP_PKEY_size(pkey)) < 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (PACKET_remaining(&signature) > (size_t)maxsig) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      SSL_R_WRONG_SIGNATURE_LENGTH);
        goto end;
    }

    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    /* verify the signature */
    if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_MALLOC_FAILURE);
        goto end;
    }

    mpctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (mpctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_PKEY_CTX_set1_id(mpctx, id, strlen(id)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, mpctx);;

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, &(s->s3->client_random[0]),
                               SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestVerifyUpdate(md_ctx, &(s->s3->server_random[0]),
                                      SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestVerifyUpdate(md_ctx, ecparams, paramslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestVerifyFinal(md_ctx, PACKET_data(&signature),
                              PACKET_remaining(&signature)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                      SSL_R_BAD_SIGNATURE);
        goto end;
    }

    ret = 1;

 end:
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(mpctx);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2DHE,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int ntls_process_ske_sm2(SSL *s, PACKET *pkt)
{
# if !defined(OPENSSL_NO_SM2) && !defined(OPENSSL_NO_SM3)
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509 *x509;
    unsigned char *buf = NULL, *p = NULL;
    int n;
    PACKET signature;
    int maxsig;
    EVP_MD_CTX *md_ctx = NULL;
    char *id = "1234567812345678";

    /* get peer's signing pkey */
    if (!(pkey = X509_get0_pubkey(s->session->peer))) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* get peer's encryption cert */
    if ((x509 = sk_X509_value(s->session->peer_chain, 1)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((n = i2d_X509(x509, NULL)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* XXX: Should the heading 3 bytes be necessary? */
    buf = OPENSSL_malloc(n + 3);
    if (buf == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    p = &(buf[3]);
    if ((n = i2d_X509(x509, &p)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    l2n3(n, buf);
    buf -= 3;

    /* get signature packet, check no data remaining */
    if (!PACKET_get_length_prefixed_2(pkt, &signature)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      SSL_R_LENGTH_MISMATCH);
        goto end;
    }

    maxsig = EVP_PKEY_size(pkey);
    if (maxsig < 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (PACKET_remaining(&signature) > (size_t)maxsig) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      SSL_R_WRONG_SIGNATURE_LENGTH);
        goto end;
    }

    /* verify the signature */
    if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    /* set pkey to SM2 */
    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_PKEY_CTX_set1_id(pctx, id, strlen(id)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pctx);;

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, &(s->s3->client_random[0]),
                               SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestVerifyUpdate(md_ctx, &(s->s3->server_random[0]),
                                      SSL3_RANDOM_SIZE) <= 0
            || EVP_DigestVerifyUpdate(md_ctx, buf, n + 3) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestVerifyFinal(md_ctx, PACKET_data(&signature),
                              PACKET_remaining(&signature)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                      SSL_R_BAD_SIGNATURE);
        goto end;
    }

    ret = 1;

end:
    OPENSSL_free(buf);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pctx);

    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_SM2,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int ntls_process_ske_rsa(SSL *s, PACKET *pkt)
{
# ifndef OPENSSL_NO_RSA
    int ret = 0;
    EVP_PKEY *pkey;
    X509 *x509;
    PACKET signature;
    int maxsig;
    unsigned char *buf = NULL, *p = NULL;
    int n;
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx = NULL;

    /* get peer's signing pkey */
    if ((pkey = X509_get0_pubkey(s->session->peer)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tls1_set_peer_legacy_sigalg(s, pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tls1_lookup_md(s->s3->tmp.peer_sigalg, &md)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* get peer's encryption cert */
    if ((x509 = sk_X509_value(s->session->peer_chain, 1)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* get signature packet, check no data remaining */
    if (!PACKET_get_length_prefixed_2(pkt, &signature)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    maxsig = EVP_PKEY_size(pkey);

    if (PACKET_remaining(&signature) > (size_t)maxsig) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      SSL_R_WRONG_SIGNATURE_LENGTH);
        return 0;
    }

    if ((n = i2d_X509(x509, NULL)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* XXX: Should the heading 3 bytes be necessary? */
    buf = OPENSSL_malloc(n + 3);
    if (buf == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    p = &(buf[3]);

    if ((n = i2d_X509(x509, &p)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    l2n3(n, buf);
    buf -= 3;

    /* verify the signature */
    if (!(md_ctx = EVP_MD_CTX_new())) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, &(s->s3->client_random[0]),
                               SSL3_RANDOM_SIZE) <= 0
        || EVP_DigestVerifyUpdate(md_ctx, &(s->s3->server_random[0]),
                                  SSL3_RANDOM_SIZE) <= 0
        || EVP_DigestVerifyUpdate(md_ctx, buf, n) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (EVP_DigestVerifyFinal(md_ctx, PACKET_data(&signature),
                              PACKET_remaining(&signature)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                      SSL_R_BAD_SIGNATURE);
        goto end;
    }

    ret = 1;

 end:
    OPENSSL_free(buf);
    EVP_MD_CTX_free(md_ctx);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_PROCESS_SKE_RSA,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

MSG_PROCESS_RETURN ntls_process_server_key_exchange_ntls(SSL *s, PACKET *pkt)
{
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    if (alg_k & SSL_kSM2DHE) {
        if (!ntls_process_ske_sm2dhe(s, pkt)) {
            /* SSLfatal_ntls already called */
            goto err;
        }
    } else if (alg_k & SSL_kSM2) {
        if (!ntls_process_ske_sm2(s, pkt)) {
            /* SSLfatal_ntls already called */
            goto err;
        }
    } else if (alg_k & SSL_kRSA) {
        if (!ntls_process_ske_rsa(s, pkt)) {
            /* SSLfatal_ntls already called */
            goto err;
        }
    } else {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                 SSL_F_NTLS_PROCESS_SERVER_KEY_EXCHANGE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return MSG_PROCESS_CONTINUE_READING;

 err:
    return MSG_PROCESS_ERROR;
}

static int ntls_construct_cke_sm2dhe(SSL *s, WPACKET *pkt)
{
# if !defined(OPENSSL_NO_SM2) && !defined(OPENSSL_NO_SM3)
    int ret = 0;
    EVP_PKEY *skey;
    EVP_PKEY *ckey = NULL;
    unsigned char *encodedPoint = NULL;
    int encodedlen;
    int curve_id;

    if ((skey = s->s3->peer_tmp) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    curve_id = tls1_shared_group(s, -2);

    /* XXX: do we need this in NTLS? */
    if (!WPACKET_put_bytes_u8(pkt, NAMED_CURVE_TYPE)
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_put_bytes_u8(pkt, curve_id)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((ckey = ssl_generate_pkey(skey)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!ntls_sm2_derive_ntls(s, ckey, skey)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (!(encodedlen = EVP_PKEY_get1_tls_encodedpoint(ckey, &encodedPoint))) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (!WPACKET_sub_memcpy_u8(pkt, encodedPoint, encodedlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2DHE,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    ret = 1;
 end:
    EVP_PKEY_free(ckey);
    OPENSSL_free(encodedPoint);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2DHE,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int ntls_construct_cke_sm2(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_SM2
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t enclen;
    unsigned char *pms = NULL;
    size_t pmslen;
    unsigned char *encbytes1, *encbytes2;
    X509 *x509;

    /* get sm2 encryption key from enc cert */
    if (s->session->peer_chain == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * XXX:
     *
     * for client side, s->session->peer == s->session->peer_chain[0] is
     * the server signing certificate.
     *
     * s->session->peer_chain[1] is the server encryption certificate
     */
    if ((x509 = sk_X509_value(s->session->peer_chain, 1)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pkey = X509_get0_pubkey(x509);
    if (EVP_PKEY_get0_EC_KEY(pkey) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* generate pre_master_secret */
    pmslen = SSL_MAX_MASTER_KEY_LENGTH;
    if ((pms = OPENSSL_malloc(pmslen)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }

    pms[0] = s->client_version >> 8;
    pms[1] = s->client_version & 0xff;

    if (RAND_bytes(pms + 2, pmslen - 2) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    /* encrypt pre_master_secret */
    if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (EVP_PKEY_encrypt_init(pctx) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (EVP_PKEY_encrypt(pctx, NULL, &enclen, pms, pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_EVP_LIB);
        goto end;
    }

    /*
     * XXX:
     * This is very unclear. The standard TLS protocol requires no u16 len
     * bytes before the encrypted PMS value. The NTLS specification is also
     * very blurry on this. But major implementations require the 2 bytes
     * length field (which is redundant), otherwise handshake will fail...
     */
    if (!WPACKET_sub_reserve_bytes_u16(pkt, enclen, &encbytes1)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (EVP_PKEY_encrypt(pctx, encbytes1, &enclen, pms, pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      SSL_R_BAD_SM2_ENCRYPT);
        goto end;
    }

    if (!WPACKET_sub_allocate_bytes_u16(pkt, enclen, &encbytes2)
            || encbytes1 != encbytes2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    /* save pre_master_secret */
    if (s->s3->tmp.pms != NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                      ERR_R_INTERNAL_ERROR);
        goto end;
    }

    s->s3->tmp.pms = pms;
    s->s3->tmp.pmslen = pmslen;
    pms = NULL;

    ret = 1;

 end:
    OPENSSL_clear_free(pms, pmslen);
    EVP_PKEY_CTX_free(pctx);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_SM2,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int ntls_construct_cke_rsa(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_RSA
    int ret = 0;
    unsigned char *encdata;
    X509 *x509;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    size_t enclen;
    unsigned char *pms = NULL;
    size_t pmslen = 0;

    if (s->session->peer_chain == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* get peer's encryption cert */
    if (!(x509 = sk_X509_value(s->session->peer_chain, 1))) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pkey = X509_get0_pubkey(x509);
    if (!EVP_PKEY_get0_RSA(pkey)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* generate pre_master_secret */
    pmslen = SSL_MAX_MASTER_KEY_LENGTH;
    if ((pms = OPENSSL_malloc(pmslen)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    pms[0] = s->client_version >> 8;
    pms[1] = s->client_version & 0xff;
    if (RAND_bytes(pms + 2, pmslen - 2) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    /* encrypt pre_master_secret and output packet */
    if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (EVP_PKEY_encrypt_init(pctx) <= 0
            || EVP_PKEY_encrypt(pctx, NULL, &enclen, pms, pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, ERR_R_EVP_LIB);
        goto end;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_RSA,
                      ERR_R_EVP_LIB);
        goto end;
    }

    /* NTLS RSA also set 2 bytes length-prefix */
    if (!WPACKET_sub_allocate_bytes_u16(pkt, enclen, &encdata)
            || EVP_PKEY_encrypt(pctx, encdata, &enclen, pms, pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_NTLS_CONSTRUCT_CKE_RSA, SSL_R_BAD_RSA_ENCRYPT);
        goto end;
    }

    /* save local pre_master_secret */
    s->s3->tmp.pms = pms;
    s->s3->tmp.pmslen = pmslen;
    pms = NULL;
    pmslen = 0;

    ret = 1;

end:
    OPENSSL_clear_free(pms, pmslen);
    EVP_PKEY_CTX_free(pctx);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CKE_RSA,
                  ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

int ntls_construct_client_key_exchange_ntls(SSL *s, WPACKET *pkt)
{
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    if (alg_k & SSL_kRSA) {
        if (!ntls_construct_cke_rsa(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kSM2) {
        if (!ntls_construct_cke_sm2(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & (SSL_kSM2DHE)) {
        if (!ntls_construct_cke_sm2dhe(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                      SSL_F_NTLS_CONSTRUCT_CLIENT_KEY_EXCHANGE_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return 1;
 err:
    return 0;
}

int ntls_construct_cert_verify_ntls(SSL *s, WPACKET *pkt)
{
    EVP_PKEY *pkey = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_MD_CTX *mctx2 = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    size_t hdatalen = 0, siglen = 0;
    void *hdata;
    unsigned char *sig = NULL;
    unsigned char out[EVP_MAX_MD_SIZE];
    size_t outlen = 0;
    const SIGALG_LOOKUP *lu = s->s3->tmp.sigalg;

    if (lu == NULL || s->s3->tmp.sign_cert == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    pkey = s->s3->tmp.sign_cert->privatekey;

    if (pkey == NULL || !tls1_lookup_md(lu, &md)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (mctx == NULL || mctx2 == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                      ERR_R_MALLOC_FAILURE);
        goto err;
    }

    hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
    if (hdatalen <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                      ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!EVP_DigestInit_ex(mctx2, md, NULL)
            || !EVP_DigestUpdate(mctx2, hdata, hdatalen)
            || !EVP_DigestFinal(mctx2, out, (unsigned int *)&outlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                      ERR_R_EVP_LIB);
        goto err;
    }

    siglen = EVP_PKEY_size(pkey);
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                      ERR_R_MALLOC_FAILURE);
        goto err;
    }
# ifndef OPENSSL_NO_SM2
    if (EVP_PKEY_is_sm2(pkey)) {
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (pctx == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                          SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                          ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (EVP_PKEY_CTX_set1_id(pctx, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LEN) <= 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                          SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                          ERR_R_EVP_LIB);
            goto err;
        }

        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    }
# endif
    if (EVP_DigestSignInit(mctx, NULL, md, NULL, pkey) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                      ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_DigestSign(mctx, sig, &siglen, out, outlen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                 ERR_R_EVP_LIB);
        goto err;
    }

    if (!WPACKET_sub_memcpy_u16(pkt, sig, siglen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_CONSTRUCT_CERT_VERIFY_NTLS,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Digest cached records and discard handshake buffer */
    if (!ssl3_digest_cached_records(s, 0)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    OPENSSL_free(sig);
    EVP_MD_CTX_free(mctx);
    EVP_MD_CTX_free(mctx2);
    EVP_PKEY_CTX_free(pctx);
    return 1;
 err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(mctx);
    EVP_MD_CTX_free(mctx2);
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

#endif
