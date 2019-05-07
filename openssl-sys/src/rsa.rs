use std::ptr;
use std::mem;

use libc::*;

use *;

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
            ) -> ::std::option::Option<
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
                pub_enc: ::std::option::Option<
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
            ) -> ::std::option::Option<
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
                pub_dec: ::std::option::Option<
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
            ) -> ::std::option::Option<
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
                priv_enc: ::std::option::Option<
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
            ) -> ::std::option::Option<
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
                priv_dec: ::std::option::Option<
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
            ) -> ::std::option::Option<
                unsafe extern "C" fn(
                    meth: *mut BIGNUM,
                    arg1: *const BIGNUM,
                    arg2: *mut RSA,
                    arg3: *mut BN_CTX,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_mod_exp(
                rsa: *mut RSA_METHOD,
                mod_exp: ::std::option::Option<
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
            ) -> ::std::option::Option<
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
                bn_mod_exp: ::std::option::Option<
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
            ) -> ::std::option::Option<unsafe extern "C" fn(meth: *mut RSA) -> c_int>;

            pub fn RSA_meth_set_init(
                rsa: *mut RSA_METHOD,
                init: ::std::option::Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
            ) -> c_int;

            pub fn RSA_meth_get_finish(
                meth: *const RSA_METHOD,
            ) -> ::std::option::Option<unsafe extern "C" fn(meth: *mut RSA) -> c_int>;

            pub fn RSA_meth_set_finish(
                rsa: *mut RSA_METHOD,
                finish: ::std::option::Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
            ) -> c_int;

            pub fn RSA_meth_get_sign(
                meth: *const RSA_METHOD,
            ) -> ::std::option::Option<
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
                sign: ::std::option::Option<
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
            ) -> ::std::option::Option<
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
                verify: ::std::option::Option<
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
            ) -> ::std::option::Option<
                unsafe extern "C" fn(
                    meth: *mut RSA,
                    arg1: c_int,
                    arg2: *mut BIGNUM,
                    arg3: *mut BN_GENCB,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_keygen(
                rsa: *mut RSA_METHOD,
                keygen: ::std::option::Option<
                    unsafe extern "C" fn(
                        rsa: *mut RSA,
                        bits: c_int,
                        e: *mut BIGNUM,
                        cb: *mut BN_GENCB,
                    ) -> c_int,
                >,
            ) -> c_int;

            pub fn RSA_meth_get_multi_prime_keygen(
                meth: *const RSA_METHOD,
            ) -> ::std::option::Option<
                unsafe extern "C" fn(
                    meth: *mut RSA,
                    arg1: c_int,
                    arg2: c_int,
                    arg3: *mut BIGNUM,
                    arg4: *mut BN_GENCB,
                ) -> c_int,
            >;

            pub fn RSA_meth_set_multi_prime_keygen(
                meth: *mut RSA_METHOD,
                keygen: ::std::option::Option<
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
