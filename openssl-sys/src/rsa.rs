use std::mem;
use std::ptr;

use libc::*;

use *;

//  Function codes.

pub const RSA_F_CHECK_PADDING_MD: i32 = 140;
pub const RSA_F_ENCODE_PKCS1: i32 = 146;
pub const RSA_F_INT_RSA_VERIFY: i32 = 145;
pub const RSA_F_OLD_RSA_PRIV_DECODE: i32 = 147;
pub const RSA_F_PKEY_PSS_INIT: i32 = 165;
pub const RSA_F_PKEY_RSA_CTRL: i32 = 143;
pub const RSA_F_PKEY_RSA_CTRL_STR: i32 = 144;
pub const RSA_F_PKEY_RSA_SIGN: i32 = 142;
pub const RSA_F_PKEY_RSA_VERIFY: i32 = 149;
pub const RSA_F_PKEY_RSA_VERIFYRECOVER: i32 = 141;
pub const RSA_F_RSA_ALGOR_TO_MD: i32 = 156;
pub const RSA_F_RSA_BUILTIN_KEYGEN: i32 = 129;
pub const RSA_F_RSA_CHECK_KEY: i32 = 123;
pub const RSA_F_RSA_CHECK_KEY_EX: i32 = 160;
pub const RSA_F_RSA_CMS_DECRYPT: i32 = 159;
pub const RSA_F_RSA_CMS_VERIFY: i32 = 158;
pub const RSA_F_RSA_ITEM_VERIFY: i32 = 148;
pub const RSA_F_RSA_METH_DUP: i32 = 161;
pub const RSA_F_RSA_METH_NEW: i32 = 162;
pub const RSA_F_RSA_METH_SET1_NAME: i32 = 163;
pub const RSA_F_RSA_MGF1_TO_MD: i32 = 157;
pub const RSA_F_RSA_MULTIP_INFO_NEW: i32 = 166;
pub const RSA_F_RSA_NEW_METHOD: i32 = 106;
pub const RSA_F_RSA_NULL: i32 = 124;
pub const RSA_F_RSA_NULL_PRIVATE_DECRYPT: i32 = 132;
pub const RSA_F_RSA_NULL_PRIVATE_ENCRYPT: i32 = 133;
pub const RSA_F_RSA_NULL_PUBLIC_DECRYPT: i32 = 134;
pub const RSA_F_RSA_NULL_PUBLIC_ENCRYPT: i32 = 135;
pub const RSA_F_RSA_OSSL_PRIVATE_DECRYPT: i32 = 101;
pub const RSA_F_RSA_OSSL_PRIVATE_ENCRYPT: i32 = 102;
pub const RSA_F_RSA_OSSL_PUBLIC_DECRYPT: i32 = 103;
pub const RSA_F_RSA_OSSL_PUBLIC_ENCRYPT: i32 = 104;
pub const RSA_F_RSA_PADDING_ADD_NONE: i32 = 107;
pub const RSA_F_RSA_PADDING_ADD_PKCS1_OAEP: i32 = 121;
pub const RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1: i32 = 154;
pub const RSA_F_RSA_PADDING_ADD_PKCS1_PSS: i32 = 125;
pub const RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1: i32 = 152;
pub const RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1: i32 = 108;
pub const RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2: i32 = 109;
pub const RSA_F_RSA_PADDING_ADD_SSLV23: i32 = 110;
pub const RSA_F_RSA_PADDING_ADD_X931: i32 = 127;
pub const RSA_F_RSA_PADDING_CHECK_NONE: i32 = 111;
pub const RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP: i32 = 122;
pub const RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1: i32 = 153;
pub const RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1: i32 = 112;
pub const RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2: i32 = 113;
pub const RSA_F_RSA_PADDING_CHECK_SSLV23: i32 = 114;
pub const RSA_F_RSA_PADDING_CHECK_X931: i32 = 128;
pub const RSA_F_RSA_PARAM_DECODE: i32 = 164;
pub const RSA_F_RSA_PRINT: i32 = 115;
pub const RSA_F_RSA_PRINT_FP: i32 = 116;
pub const RSA_F_RSA_PRIV_DECODE: i32 = 150;
pub const RSA_F_RSA_PRIV_ENCODE: i32 = 138;
pub const RSA_F_RSA_PSS_GET_PARAM: i32 = 151;
pub const RSA_F_RSA_PSS_TO_CTX: i32 = 155;
pub const RSA_F_RSA_PUB_DECODE: i32 = 139;
pub const RSA_F_RSA_SETUP_BLINDING: i32 = 136;
pub const RSA_F_RSA_SIGN: i32 = 117;
pub const RSA_F_RSA_SIGN_ASN1_OCTET_STRING: i32 = 118;
pub const RSA_F_RSA_VERIFY: i32 = 119;
pub const RSA_F_RSA_VERIFY_ASN1_OCTET_STRING: i32 = 120;
pub const RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1: i32 = 126;
pub const RSA_F_SETUP_TBUF: i32 = 167;

// Reason codes.

pub const RSA_R_ALGORITHM_MISMATCH: u32 = 100;
pub const RSA_R_BAD_E_VALUE: u32 = 101;
pub const RSA_R_BAD_FIXED_HEADER_DECRYPT: u32 = 102;
pub const RSA_R_BAD_PAD_BYTE_COUNT: u32 = 103;
pub const RSA_R_BAD_SIGNATURE: u32 = 104;
pub const RSA_R_BLOCK_TYPE_IS_NOT_01: u32 = 106;
pub const RSA_R_BLOCK_TYPE_IS_NOT_02: u32 = 107;
pub const RSA_R_DATA_GREATER_THAN_MOD_LEN: u32 = 108;
pub const RSA_R_DATA_TOO_LARGE: u32 = 109;
pub const RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE: u32 = 110;
pub const RSA_R_DATA_TOO_LARGE_FOR_MODULUS: u32 = 132;
pub const RSA_R_DATA_TOO_SMALL: u32 = 111;
pub const RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE: u32 = 122;
pub const RSA_R_DIGEST_DOES_NOT_MATCH: u32 = 158;
pub const RSA_R_DIGEST_NOT_ALLOWED: u32 = 145;
pub const RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY: u32 = 112;
pub const RSA_R_DMP1_NOT_CONGRUENT_TO_D: u32 = 124;
pub const RSA_R_DMQ1_NOT_CONGRUENT_TO_D: u32 = 125;
pub const RSA_R_D_E_NOT_CONGRUENT_TO_1: u32 = 123;
pub const RSA_R_FIRST_OCTET_INVALID: u32 = 133;
pub const RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE: u32 = 144;
pub const RSA_R_INVALID_DIGEST: u32 = 157;
pub const RSA_R_INVALID_DIGEST_LENGTH: u32 = 143;
pub const RSA_R_INVALID_HEADER: u32 = 137;
pub const RSA_R_INVALID_LABEL: u32 = 160;
pub const RSA_R_INVALID_MESSAGE_LENGTH: u32 = 131;
pub const RSA_R_INVALID_MGF1_MD: u32 = 156;
pub const RSA_R_INVALID_MULTI_PRIME_KEY: u32 = 167;
pub const RSA_R_INVALID_OAEP_PARAMETERS: u32 = 161;
pub const RSA_R_INVALID_PADDING: u32 = 138;
pub const RSA_R_INVALID_PADDING_MODE: u32 = 141;
pub const RSA_R_INVALID_PSS_PARAMETERS: u32 = 149;
pub const RSA_R_INVALID_PSS_SALTLEN: u32 = 146;
pub const RSA_R_INVALID_SALT_LENGTH: u32 = 150;
pub const RSA_R_INVALID_TRAILER: u32 = 139;
pub const RSA_R_INVALID_X931_DIGEST: u32 = 142;
pub const RSA_R_IQMP_NOT_INVERSE_OF_Q: u32 = 126;
pub const RSA_R_KEY_PRIME_NUM_INVALID: u32 = 165;
pub const RSA_R_KEY_SIZE_TOO_SMALL: u32 = 120;
pub const RSA_R_LAST_OCTET_INVALID: u32 = 134;
pub const RSA_R_MGF1_DIGEST_NOT_ALLOWED: u32 = 152;
pub const RSA_R_MODULUS_TOO_LARGE: u32 = 105;
pub const RSA_R_MP_COEFFICIENT_NOT_INVERSE_OF_R: u32 = 168;
pub const RSA_R_MP_EXPONENT_NOT_CONGRUENT_TO_D: u32 = 169;
pub const RSA_R_MP_R_NOT_PRIME: u32 = 170;
pub const RSA_R_NO_PUBLIC_EXPONENT: u32 = 140;
pub const RSA_R_NULL_BEFORE_BLOCK_MISSING: u32 = 113;
pub const RSA_R_N_DOES_NOT_EQUAL_PRODUCT_OF_PRIMES: u32 = 172;
pub const RSA_R_N_DOES_NOT_EQUAL_P_Q: u32 = 127;
pub const RSA_R_OAEP_DECODING_ERROR: u32 = 121;
pub const RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE: u32 = 148;
pub const RSA_R_PADDING_CHECK_FAILED: u32 = 114;
pub const RSA_R_PKCS_DECODING_ERROR: u32 = 159;
pub const RSA_R_PSS_SALTLEN_TOO_SMALL: u32 = 164;
pub const RSA_R_P_NOT_PRIME: u32 = 128;
pub const RSA_R_Q_NOT_PRIME: u32 = 129;
pub const RSA_R_RSA_OPERATIONS_NOT_SUPPORTED: u32 = 130;
pub const RSA_R_SLEN_CHECK_FAILED: u32 = 136;
pub const RSA_R_SLEN_RECOVERY_FAILED: u32 = 135;
pub const RSA_R_SSLV3_ROLLBACK_ATTACK: u32 = 115;
pub const RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD: u32 = 116;
pub const RSA_R_UNKNOWN_ALGORITHM_TYPE: u32 = 117;
pub const RSA_R_UNKNOWN_DIGEST: u32 = 166;
pub const RSA_R_UNKNOWN_MASK_DIGEST: u32 = 151;
pub const RSA_R_UNKNOWN_PADDING_TYPE: u32 = 118;
pub const RSA_R_UNSUPPORTED_ENCRYPTION_TYPE: u32 = 162;
pub const RSA_R_UNSUPPORTED_LABEL_SOURCE: u32 = 163;
pub const RSA_R_UNSUPPORTED_MASK_ALGORITHM: u32 = 153;
pub const RSA_R_UNSUPPORTED_MASK_PARAMETER: u32 = 154;
pub const RSA_R_UNSUPPORTED_SIGNATURE_TYPE: u32 = 155;
pub const RSA_R_VALUE_MISSING: u32 = 147;
pub const RSA_R_WRONG_SIGNATURE_LENGTH: u32 = 119;

pub const RSA_F4: c_long = 0x10001;

pub unsafe fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad: c_int) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        EVP_PKEY_RSA,
        -1,
        EVP_PKEY_CTRL_RSA_PADDING,
        pad,
        ptr::null_mut(),
    )
}

pub unsafe fn EVP_PKEY_CTX_get_rsa_padding(ctx: *mut EVP_PKEY_CTX, ppad: *mut c_int) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        EVP_PKEY_RSA,
        -1,
        EVP_PKEY_CTRL_GET_RSA_PADDING,
        0,
        ppad as *mut c_void,
    )
}

pub unsafe fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, len: c_int) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        EVP_PKEY_RSA,
        EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY,
        EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
        len,
        ptr::null_mut(),
    )
}

pub unsafe fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *mut EVP_MD) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        EVP_PKEY_RSA,
        EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
        EVP_PKEY_CTRL_RSA_MGF1_MD,
        0,
        md as *mut c_void,
    )
}

pub const EVP_PKEY_CTRL_RSA_PADDING: c_int = EVP_PKEY_ALG_CTRL + 1;
pub const EVP_PKEY_CTRL_RSA_PSS_SALTLEN: c_int = EVP_PKEY_ALG_CTRL + 2;

pub const EVP_PKEY_CTRL_RSA_MGF1_MD: c_int = EVP_PKEY_ALG_CTRL + 5;

pub const EVP_PKEY_CTRL_GET_RSA_PADDING: c_int = EVP_PKEY_ALG_CTRL + 6;

pub const RSA_PKCS1_PADDING: c_int = 1;
pub const RSA_SSLV23_PADDING: c_int = 2;
pub const RSA_NO_PADDING: c_int = 3;
pub const RSA_PKCS1_OAEP_PADDING: c_int = 4;
pub const RSA_X931_PADDING: c_int = 5;
pub const RSA_PKCS1_PSS_PADDING: c_int = 6;

extern "C" {
    pub fn RSA_new() -> *mut RSA;
    pub fn RSA_size(k: *const RSA) -> c_int;

    #[cfg(any(ossl110, libressl273))]
    pub fn RSA_set0_key(
        r: *mut ::RSA,
        n: *mut ::BIGNUM,
        e: *mut ::BIGNUM,
        d: *mut ::BIGNUM,
    ) -> c_int;
    #[cfg(any(ossl110, libressl273))]
    pub fn RSA_set0_factors(r: *mut ::RSA, p: *mut ::BIGNUM, q: *mut ::BIGNUM) -> c_int;
    #[cfg(any(ossl110, libressl273))]
    pub fn RSA_set0_crt_params(
        r: *mut ::RSA,
        dmp1: *mut ::BIGNUM,
        dmq1: *mut ::BIGNUM,
        iqmp: *mut ::BIGNUM,
    ) -> c_int;
    #[cfg(any(ossl110, libressl273))]
    pub fn RSA_get0_key(
        r: *const ::RSA,
        n: *mut *const ::BIGNUM,
        e: *mut *const ::BIGNUM,
        d: *mut *const ::BIGNUM,
    );
    #[cfg(any(ossl110, libressl273))]
    pub fn RSA_get0_factors(r: *const ::RSA, p: *mut *const ::BIGNUM, q: *mut *const ::BIGNUM);
    #[cfg(any(ossl110, libressl273))]
    pub fn RSA_get0_crt_params(
        r: *const ::RSA,
        dmp1: *mut *const ::BIGNUM,
        dmq1: *mut *const ::BIGNUM,
        iqmp: *mut *const ::BIGNUM,
    );

    #[cfg(not(ossl110))]
    pub fn RSA_generate_key(
        modsz: c_int,
        e: c_ulong,
        cb: Option<extern "C" fn(c_int, c_int, *mut c_void)>,
        cbarg: *mut c_void,
    ) -> *mut RSA;

    pub fn RSA_generate_key_ex(
        rsa: *mut RSA,
        bits: c_int,
        e: *mut BIGNUM,
        cb: *mut BN_GENCB,
    ) -> c_int;

    pub fn RSA_public_encrypt(
        flen: c_int,
        from: *const u8,
        to: *mut u8,
        k: *mut RSA,
        pad: c_int,
    ) -> c_int;
    pub fn RSA_private_encrypt(
        flen: c_int,
        from: *const u8,
        to: *mut u8,
        k: *mut RSA,
        pad: c_int,
    ) -> c_int;
    pub fn RSA_public_decrypt(
        flen: c_int,
        from: *const u8,
        to: *mut u8,
        k: *mut RSA,
        pad: c_int,
    ) -> c_int;
    pub fn RSA_private_decrypt(
        flen: c_int,
        from: *const u8,
        to: *mut u8,
        k: *mut RSA,
        pad: c_int,
    ) -> c_int;
    pub fn RSA_check_key(r: *const ::RSA) -> c_int;
    pub fn RSA_free(rsa: *mut RSA);
    pub fn RSA_up_ref(rsa: *mut RSA) -> c_int;

    pub fn i2d_RSAPublicKey(k: *const RSA, buf: *mut *mut u8) -> c_int;
    pub fn d2i_RSAPublicKey(k: *mut *mut RSA, buf: *mut *const u8, len: c_long) -> *mut RSA;
    pub fn i2d_RSAPrivateKey(k: *const RSA, buf: *mut *mut u8) -> c_int;
    pub fn d2i_RSAPrivateKey(k: *mut *mut RSA, buf: *mut *const u8, len: c_long) -> *mut RSA;

    pub fn RSA_sign(
        t: c_int,
        m: *const u8,
        mlen: c_uint,
        sig: *mut u8,
        siglen: *mut c_uint,
        k: *mut RSA,
    ) -> c_int;
    pub fn RSA_verify(
        t: c_int,
        m: *const u8,
        mlen: c_uint,
        sig: *const u8,
        siglen: c_uint,
        k: *mut RSA,
    ) -> c_int;

    pub fn RSA_padding_check_PKCS1_type_2(
        to: *mut c_uchar,
        tlen: c_int,
        f: *const c_uchar,
        fl: c_int,
        rsa_len: c_int,
    ) -> c_int;

    pub fn RSA_get_ex_data(r: *const RSA, idx: c_int) -> *mut c_void;

    pub fn RSA_set_ex_data(r: *mut RSA, idx: c_int, arg: *mut c_void) -> c_int;
}

cfg_if! {
    if #[cfg(ossl110)] {
        pub unsafe fn RSA_get_ex_new_index(
            argl: c_long,
            argp: *mut c_void,
            new_func: CRYPTO_EX_new,
            dup_func: CRYPTO_EX_dup,
            free_func: CRYPTO_EX_free,
        ) -> c_int {
            CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, argl, argp, new_func, dup_func, free_func)
        }
    } else {
        extern "C" {
            pub fn RSA_get_ex_new_index(
                argl: c_long,
                argp: *mut c_void,
                new_func: CRYPTO_EX_new,
                dup_func: CRYPTO_EX_dup,
                free_func: CRYPTO_EX_free,
            ) -> c_int;
        }
    }
}

pub const RSA_METHOD_FLAG_NO_CHECK: u32 = 0x0001;

extern "C" {
    pub fn RSA_get_default_method() -> *const RSA_METHOD;

    pub fn RSA_set_default_method(meth: *const RSA_METHOD);

    pub fn RSA_get_method(rsa: *const RSA) -> *const RSA_METHOD;

    pub fn RSA_set_method(rsa: *mut RSA, meth: *const RSA_METHOD) -> c_int;
}

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn RSA_PKCS1_OpenSSL() -> *const RSA_METHOD;
        }
    } else {
        extern "C" {
            pub fn RSA_PKCS1_SSLeay() -> *const RSA_METHOD;
        }
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn RSA_meth_new(
                name: *const c_char,
                flags: c_int,
            ) -> *mut RSA_METHOD;

            pub fn RSA_meth_free(meth: *mut RSA_METHOD);

            pub fn RSA_meth_dup(meth: *const RSA_METHOD) -> *mut RSA_METHOD;

            pub fn RSA_meth_get0_name(meth: *const RSA_METHOD) -> *const c_char;

            pub fn RSA_meth_set1_name(
                meth: *mut RSA_METHOD,
                name: *const c_char,
            ) -> c_int;

            pub fn RSA_meth_get_flags(meth: *const RSA_METHOD) -> c_int;

            pub fn RSA_meth_set_flags(
                meth: *mut RSA_METHOD,
                flags: c_int,
            ) -> c_int;

            pub fn RSA_meth_get0_app_data(meth: *const RSA_METHOD) -> *mut c_void;

            pub fn RSA_meth_set0_app_data(
                meth: *mut RSA_METHOD,
                app_data: *mut c_void,
            ) -> c_int;

            pub fn RSA_meth_get_pub_enc(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: c_int,
                    arg1: *const c_uchar,
                    arg2: *mut c_uchar,
                    arg3: *mut RSA,
                    arg4: c_int,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_pub_enc(
                rsa: *mut RSA_METHOD,
                pub_enc: Option<
                    unsafe extern "C" fn(
                        flen: c_int,
                        from: *const c_uchar,
                        to: *mut c_uchar,
                        rsa: *mut RSA,
                        padding: c_int,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_pub_dec(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: c_int,
                    arg1: *const c_uchar,
                    arg2: *mut c_uchar,
                    arg3: *mut RSA,
                    arg4: c_int,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_pub_dec(
                rsa: *mut RSA_METHOD,
                pub_dec: Option<
                    unsafe extern "C" fn(
                        flen: c_int,
                        from: *const c_uchar,
                        to: *mut c_uchar,
                        rsa: *mut RSA,
                        padding: c_int,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_priv_enc(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: c_int,
                    arg1: *const c_uchar,
                    arg2: *mut c_uchar,
                    arg3: *mut RSA,
                    arg4: c_int,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_priv_enc(
                rsa: *mut RSA_METHOD,
                priv_enc: Option<
                    unsafe extern "C" fn(
                        flen: c_int,
                        from: *const c_uchar,
                        to: *mut c_uchar,
                        rsa: *mut RSA,
                        padding: c_int,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_priv_dec(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: c_int,
                    arg1: *const c_uchar,
                    arg2: *mut c_uchar,
                    arg3: *mut RSA,
                    arg4: c_int,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_priv_dec(
                rsa: *mut RSA_METHOD,
                priv_dec: Option<
                    unsafe extern "C" fn(
                        flen: c_int,
                        from: *const c_uchar,
                        to: *mut c_uchar,
                        rsa: *mut RSA,
                        padding: c_int,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_mod_exp(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: *mut BIGNUM,
                    arg1: *const BIGNUM,
                    arg2: *mut RSA,
                    arg3: *mut BN_CTX,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_mod_exp(
                rsa: *mut RSA_METHOD,
                mod_exp: Option<
                    unsafe extern "C" fn(
                        r0: *mut BIGNUM,
                        i: *const BIGNUM,
                        rsa: *mut RSA,
                        ctx: *mut BN_CTX,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_bn_mod_exp(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: *mut BIGNUM,
                    arg1: *const BIGNUM,
                    arg2: *const BIGNUM,
                    arg3: *const BIGNUM,
                    arg4: *mut BN_CTX,
                    arg5: *mut BN_MONT_CTX,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_bn_mod_exp(
                rsa: *mut RSA_METHOD,
                bn_mod_exp: Option<
                    unsafe extern "C" fn(
                        r: *mut BIGNUM,
                        a: *const BIGNUM,
                        p: *const BIGNUM,
                        m: *const BIGNUM,
                        ctx: *mut BN_CTX,
                        m_ctx: *mut BN_MONT_CTX,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_init(
                meth: *const RSA_METHOD,
            ) -> Option<unsafe extern "C" fn(meth: *mut RSA) -> c_int>;

            pub fn RSA_meth_set_init(
                rsa: *mut RSA_METHOD,
                init: Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
            ) -> c_int;

            pub fn RSA_meth_get_finish(
                meth: *const RSA_METHOD,
            ) -> Option<unsafe extern "C" fn(meth: *mut RSA) -> c_int>;

            pub fn RSA_meth_set_finish(
                rsa: *mut RSA_METHOD,
                finish: Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
            ) -> c_int;

            pub fn RSA_meth_get_sign(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: c_int,
                    arg1: *const c_uchar,
                    arg2: c_uint,
                    arg3: *mut c_uchar,
                    arg4: *mut c_uint,
                    arg5: *const RSA,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_sign(
                rsa: *mut RSA_METHOD,
                sign: Option<
                    unsafe extern "C" fn(
                        type_: c_int,
                        m: *const c_uchar,
                        m_length: c_uint,
                        sigret: *mut c_uchar,
                        siglen: *mut c_uint,
                        rsa: *const RSA,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_verify(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: c_int,
                    arg1: *const c_uchar,
                    arg2: c_uint,
                    arg3: *const c_uchar,
                    arg4: c_uint,
                    arg5: *const RSA,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_verify(
                rsa: *mut RSA_METHOD,
                verify: Option<
                    unsafe extern "C" fn(
                        dtype: c_int,
                        m: *const c_uchar,
                        m_length: c_uint,
                        sigbuf: *const c_uchar,
                        siglen: c_uint,
                        rsa: *const RSA,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_keygen(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: *mut RSA,
                    arg1: c_int,
                    arg2: *mut BIGNUM,
                    arg3: *mut BN_GENCB,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_keygen(
                rsa: *mut RSA_METHOD,
                keygen: Option<
                    unsafe extern "C" fn(
                        rsa: *mut RSA,
                        bits: c_int,
                        e: *mut BIGNUM,
                        cb: *mut BN_GENCB,
                    ) -> c_int,
                >,
            ) -> c_int;

            #[cfg(ossl111)]
            pub fn RSA_meth_get_multi_prime_keygen(
                meth: *const RSA_METHOD,
            ) -> Option<
                unsafe extern "C" fn(
                    meth: *mut RSA,
                    arg1: c_int,
                    arg2: c_int,
                    arg3: *mut BIGNUM,
                    arg4: *mut BN_GENCB,
                ) -> c_int,
            >;

            #[cfg(ossl111)]
            pub fn RSA_meth_set_multi_prime_keygen(
                meth: *mut RSA_METHOD,
                keygen: Option<
                    unsafe extern "C" fn(
                        rsa: *mut RSA,
                        bits: c_int,
                        primes: c_int,
                        e: *mut BIGNUM,
                        cb: *mut BN_GENCB,
                    ) -> c_int,
                >,
            ) -> c_int;
        }
    }
}
