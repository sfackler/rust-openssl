use super::super::*;
use libc::*;

/* OpenSSL 3.* only */

extern "C" {
    pub fn OSSL_PARAM_BLD_new() -> *mut OSSL_PARAM_BLD;
    pub fn OSSL_PARAM_BLD_free(bld: *mut OSSL_PARAM_BLD);
    pub fn OSSL_PARAM_BLD_push_BN(
        bld: *mut OSSL_PARAM_BLD,
        key: *const c_char,
        bn: *const BIGNUM,
    ) -> c_int;
    pub fn OSSL_PARAM_BLD_push_utf8_string(
        bld: *mut OSSL_PARAM_BLD,
        key: *const c_char,
        buf: *const c_char,
        bsize: usize,
    ) -> c_int;
    pub fn OSSL_PARAM_BLD_push_octet_string(
        bld: *mut OSSL_PARAM_BLD,
        key: *const c_char,
        buf: *const c_void,
        bsize: usize,
    ) -> c_int;
    pub fn OSSL_PARAM_BLD_push_uint(
        bld: *mut OSSL_PARAM_BLD,
        key: *const c_char,
        buf: c_uint,
    ) -> c_int;
    pub fn OSSL_PARAM_BLD_to_param(bld: *mut OSSL_PARAM_BLD) -> *mut OSSL_PARAM;
}
