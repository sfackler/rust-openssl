use super::super::*;
use libc::*;

extern "C" {
    pub fn OSSL_PARAM_free(p: *mut OSSL_PARAM);
    pub fn OSSL_PARAM_construct_uint(key: *const c_char, buf: *mut c_uint) -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
    pub fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: size_t,
    ) -> OSSL_PARAM;

    pub fn OSSL_PARAM_locate(p: *mut OSSL_PARAM, key: *const c_char) -> *mut OSSL_PARAM;
    pub fn OSSL_PARAM_get_BN(p: *const OSSL_PARAM, val: *mut *mut BIGNUM) -> c_int;
    pub fn OSSL_PARAM_get_utf8_string(
        p: *const OSSL_PARAM,
        val: *mut *mut c_char,
        max_len: usize,
    ) -> c_int;
    pub fn OSSL_PARAM_get_utf8_string_ptr(p: *const OSSL_PARAM, val: *mut *const c_char) -> c_int;
    pub fn OSSL_PARAM_get_octet_string(
        p: *const OSSL_PARAM,
        val: *mut *mut c_void,
        max_len: usize,
        used_len: *mut usize,
    ) -> c_int;
    pub fn OSSL_PARAM_get_octet_string_ptr(
        p: *const OSSL_PARAM,
        val: *mut *const c_void,
        used_len: *mut usize,
    ) -> c_int;
}
