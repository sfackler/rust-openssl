#include <openssl/bn.h>

int bn_is_zero(BIGNUM *x) { return BN_is_zero(x); }

