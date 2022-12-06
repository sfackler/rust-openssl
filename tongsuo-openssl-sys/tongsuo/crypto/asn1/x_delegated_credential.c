#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include "../../ssl/packet_local.h"
#include "../../ssl/ssl_local.h"
#include "internal/refcount.h"

#ifndef OPENSSL_NO_DELEGATED_CREDENTIAL
#define MAX_SIGNATURE_LEN 65535



DELEGATED_CREDENTIAL *DC_new(void)
{
    DELEGATED_CREDENTIAL *dc;

    dc = OPENSSL_zalloc(sizeof(DELEGATED_CREDENTIAL));

    if (dc == NULL) {
         ASN1err(ASN1_F_DC_NEW, ERR_R_MALLOC_FAILURE);
         return NULL;
    }
    dc->references = 1;
    dc->lock = CRYPTO_THREAD_lock_new();
    if (dc->lock == NULL) {
        ASN1err(ASN1_F_DC_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(dc);
        return NULL;
    }
    return dc;
}

void DC_free(DELEGATED_CREDENTIAL *dc)
{
    int i;

    if (dc == NULL)
        return;

    CRYPTO_DOWN_REF(&dc->references, &i, dc->lock);
    REF_PRINT_COUNT("DC", dc);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
    CRYPTO_THREAD_lock_free(dc->lock);

    OPENSSL_free(dc->dc_publickey_raw);
    OPENSSL_free(dc->dc_signature);
    EVP_PKEY_free(dc->pkey);
    OPENSSL_free(dc->raw_byte);
    OPENSSL_free(dc);
}

int DC_up_ref(DELEGATED_CREDENTIAL *dc)
{
    int i;

    if (CRYPTO_UP_REF(&dc->references, &i, dc->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("DC", dc);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}


DELEGATED_CREDENTIAL *DC_new_from_raw_byte(const unsigned char *byte,
                                           unsigned long len)
{
    unsigned long         valid_time;
    unsigned int          expected_cert_verify_algorithm;
    unsigned long         dc_publickey_raw_len;
    unsigned char        *dc_publickey_raw = NULL;
    unsigned int          signature_sign_algorithm;
    unsigned int          dc_signature_len;
    unsigned char        *dc_signature = NULL;
    PACKET                pkt;
    DELEGATED_CREDENTIAL *dc = NULL;
    EVP_PKEY             *pkey = NULL;

    dc = DC_new();

    if (dc == NULL) {
         ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, ERR_R_MALLOC_FAILURE);
         return NULL;
    }

    if(!DC_set1_raw_byte(dc, byte, len)) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!PACKET_buf_init(&pkt, dc->raw_byte, dc->raw_byte_len))
        goto err;

    if (PACKET_remaining(&pkt) <= 0) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!PACKET_get_net_4(&pkt, &valid_time)
        || !PACKET_get_net_2(&pkt, &expected_cert_verify_algorithm)
        || !PACKET_get_net_3(&pkt, &dc_publickey_raw_len)) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }
    dc->valid_time = valid_time;
    dc->expected_cert_verify_algorithm = expected_cert_verify_algorithm;
    dc->dc_publickey_raw_len = dc_publickey_raw_len;

    if (dc_publickey_raw_len > pkt.remaining) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }
    dc_publickey_raw = OPENSSL_malloc(dc_publickey_raw_len);
    if (dc_publickey_raw == NULL) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    dc->dc_publickey_raw = dc_publickey_raw;

    if (!PACKET_copy_bytes(&pkt, dc_publickey_raw, dc_publickey_raw_len)) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }

    pkey = d2i_PUBKEY(NULL, (const unsigned char **)&dc_publickey_raw,
                             dc_publickey_raw_len);
    if (pkey == NULL) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }
    dc->pkey = pkey;

    if (!PACKET_get_net_2(&pkt, &signature_sign_algorithm)
        || !PACKET_get_net_2(&pkt, &dc_signature_len)) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }
    dc->signature_sign_algorithm = signature_sign_algorithm;

    if (dc_signature_len > pkt.remaining) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }
    dc->dc_signature_len = dc_signature_len;
    dc_signature = OPENSSL_malloc(dc_signature_len);
    if (dc_signature == NULL) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }
    dc->dc_signature = dc_signature;

    if (!PACKET_copy_bytes(&pkt, dc_signature, dc_signature_len)) {
        ASN1err(ASN1_F_DC_NEW_FROM_RAW_BYTE, SSL_R_BAD_PACKET);
        goto err;
    }

    return dc;
err:
    DC_free(dc);
    return NULL;
}

DELEGATED_CREDENTIAL *DC_load_from_file(const char *file)
{
    DELEGATED_CREDENTIAL *dc = NULL;
    BIO *bio_dc = NULL;
    unsigned char dc_buf[MAX_SIGNATURE_LEN] = {0};
    unsigned char *dc_hex_byte = NULL;
    long dc_len = 0;

    bio_dc = BIO_new_file(file, "r");
    if (bio_dc == NULL) {
        goto err;
    }

    dc_len = BIO_read(bio_dc, dc_buf, 4096);
    if (dc_len <= 0) {
        goto err;
    }
    if (dc_buf[dc_len-1] == '\n')
        dc_buf[dc_len-1] = 0;

    /*
     * parse from hex byte, just for tmp, because there is no
     * standard dc format define
     */
    dc_hex_byte = OPENSSL_hexstr2buf((const char *)dc_buf, &dc_len);
    if (dc_hex_byte == NULL)
        goto err;

    dc = DC_new_from_raw_byte(dc_hex_byte, dc_len);
    if (dc == NULL)
        goto err;

err:
    OPENSSL_free(dc_hex_byte);
    BIO_free(bio_dc);
    return dc;
}
#endif
