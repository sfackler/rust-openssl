/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#ifndef OPENSSL_NO_ZUC

# include <stdlib.h>
# include <string.h>
# include <openssl/crypto.h>

# include "crypto/zuc.h"

struct eia3_context {
    ZUC_KEY zk;
    size_t num;
    size_t length;  /* The bits of the input message */
    uint32_t T;
};

#endif
