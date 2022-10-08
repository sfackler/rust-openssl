/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#ifndef HEADER_EC_ELGAMAL_H
# define HEADER_EC_ELGAMAL_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_EC_ELGAMAL
# ifdef  __cplusplus
extern "C" {
# endif

# include <stdlib.h>
# include <openssl/ec.h>
# include <openssl/bn.h>
# include <openssl/lhash.h>
# include <crypto/lhash.h>
# include <crypto/ec.h>
# include <crypto/ec/ec_local.h>

struct ec_elgamal_ciphertext_st {
    EC_POINT *C1;
    EC_POINT *C2;
};

typedef struct ec_elgamal_decrypt_table_entry_st {
    int32_t value;
    uint32_t key_len;
    unsigned char *key;
} EC_ELGAMAL_dec_tbl_entry;

DEFINE_LHASH_OF(EC_ELGAMAL_dec_tbl_entry);

struct ec_elgamal_decrypt_table_st {
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
    int32_t decrypt_negative;
    int32_t size;
    EC_POINT *mG_inv;
    LHASH_OF(EC_ELGAMAL_dec_tbl_entry) *entries;
};

struct ec_elgamal_ctx_st {
    EC_KEY *key;
    EC_ELGAMAL_DECRYPT_TABLE *decrypt_table;
};

# ifdef  __cplusplus
}
# endif
# endif

#endif
