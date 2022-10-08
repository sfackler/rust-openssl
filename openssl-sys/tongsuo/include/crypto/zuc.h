/*
 * Copyright 2021 Ant Group. All Rights Reserved.
 * Copyright 2018 BaishanCloud. All Rights Reserved.
 */

#ifndef HEADER_ZUC_H
# define HEADER_ZUC_H

# include <openssl/opensslconf.h>
# include <openssl/e_os2.h>

# ifdef OPENSSL_NO_ZUC
#  error ZUC is disabled.
# endif

#define EVP_ZUC_KEY_SIZE 16
#define EIA3_DIGEST_SIZE 4

typedef struct ZUC_KEY_st {
    /* Linear Feedback Shift Register cells */
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;

    /* the outputs of BitReorganization */
    uint32_t X0, X1, X2, X3;

    /* non linear function F cells */
    uint32_t R1, R2;

    const uint8_t *k;
    uint8_t iv[16];

    /* keystream */
    uint8_t *keystream;
    uint32_t keystream_len;
    int L;

    int inited;
} ZUC_KEY;

typedef struct eia3_context EIA3_CTX;

void ZUC_init(ZUC_KEY *zk);
int ZUC_generate_keystream(ZUC_KEY *zk);
void ZUC_destroy_keystream(ZUC_KEY *zk);

size_t EIA3_ctx_size(void);
int EIA3_Init(EIA3_CTX *ctx, const unsigned char key[EVP_ZUC_KEY_SIZE], const unsigned char iv[5]);
int EIA3_Update(EIA3_CTX *ctx, const unsigned char *inp, size_t len);
void EIA3_Final(EIA3_CTX *ctx, unsigned char out[EIA3_DIGEST_SIZE]);

#endif
