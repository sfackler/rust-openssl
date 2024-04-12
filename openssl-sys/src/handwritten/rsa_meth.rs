use super::super::*;
use libc::*;

#[cfg(ossl110)]
extern "C" {
    pub fn RSA_meth_new(name: *const c_char, flags: c_int) -> *mut RSA_METHOD;

    pub fn RSA_meth_free(meth: *mut RSA_METHOD);

    pub fn RSA_meth_dup(meth: *const RSA_METHOD) -> *mut RSA_METHOD;

    pub fn RSA_meth_get0_name(meth: *const RSA_METHOD) -> *const c_char;
    pub fn RSA_meth_set1_name(meth: *mut RSA_METHOD, name: *const c_char) -> c_int;

    pub fn RSA_meth_get_flags(meth: *const RSA_METHOD) -> c_int;
    pub fn RSA_meth_set_flags(meth: *mut RSA_METHOD, flags: c_int) -> c_int;

    pub fn RSA_meth_get0_app_data(meth: *const RSA_METHOD) -> *mut c_void;
    pub fn RSA_meth_set0_app_data(meth: *mut RSA_METHOD, app_data: *mut c_void) -> c_int;

    pub fn RSA_meth_set_pub_enc(
        rsa: *mut RSA_METHOD,
        pub_enc: Option<extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int>,
    ) -> c_int;

    pub fn RSA_meth_set_pub_dec(
        rsa: *mut RSA_METHOD,
        pub_dec: Option<extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int>,
    ) -> c_int;

    pub fn RSA_meth_set_priv_enc(
        rsa: *mut RSA_METHOD,
        priv_enc: Option<extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int>,
    ) -> c_int;
    pub fn RSA_meth_set_priv_dec(
        rsa: *mut RSA_METHOD,
        priv_dec: Option<extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int>,
    ) -> c_int;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_mod_exp(
        rsa: *mut RSA_METHOD,
        mod_exp: Option<extern "C" fn(
            r0: *mut BIGNUM,
            i: *const BIGNUM,
            rsa: *mut RSA,
            ctx: *mut BN_CTX,
        ) -> c_int>,
    ) -> c_int;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_bn_mod_exp(
        rsa: *mut RSA_METHOD,
        bn_mod_exp: Option<extern "C" fn(
            r: *mut BIGNUM,
            a: *const BIGNUM,
            p: *const BIGNUM,
            m: *const BIGNUM,
            ctx: *mut BN_CTX,
            m_ctx: *mut BN_MONT_CTX,
        ) -> c_int>,
    ) -> c_int;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_init(
        rsa: *mut RSA_METHOD,
        init: Option<extern "C" fn(rsa: *mut RSA) -> c_int>,
    ) -> c_int;

    /// Notes from OpenSSL documentation: Can be null.
    pub fn RSA_meth_set_finish(
        rsa: *mut RSA_METHOD,
        finish: Option<extern "C" fn(rsa: *mut RSA) -> c_int>,
    ) -> c_int;

    pub fn RSA_meth_set_sign(
        rsa: *mut RSA_METHOD,
        sign: Option<extern "C" fn(
            _type: c_int,
            m: *const c_uchar,
            m_length: c_uint,
            sigret: *mut c_uchar,
            siglen: *mut c_uint,
            rsa: *const RSA,
        ) -> c_int>,
    ) -> c_int;

    pub fn RSA_meth_set_verify(
        rsa: *mut RSA_METHOD,
        verify: Option<extern "C" fn(
            dtype: c_int,
            m: *const c_uchar,
            m_length: c_uint,
            sigbuf: *const c_uchar,
            siglen: c_uint,
            rsa: *const RSA,
        ) -> c_int>,
    ) -> c_int;

    pub fn RSA_meth_set_keygen(
        rsa: *mut RSA_METHOD,
        keygen: Option<extern "C" fn(
            rsa: *mut RSA,
            bits: c_int,
            e: *mut BIGNUM,
            cb: *mut BN_GENCB,
        ) -> c_int>,
    ) -> c_int;

    #[cfg(ossl111)]
    pub fn RSA_meth_set_multi_prime_keygen(
        meth: *mut RSA_METHOD,
        keygen: Option<extern "C" fn(
            rsa: *mut RSA,
            bits: c_int,
            primes: c_int,
            e: *mut BIGNUM,
            cb: *mut BN_GENCB,
        ) -> c_int>,
    ) -> c_int;
}
