use ffi;
use libc::{c_int, c_void, c_uint, c_uchar};

#[allow(dead_code)]
extern "C" {
    pub fn rust_0_8_SSL_CTX_clone(cxt: *mut ffi::SSL_CTX);
    pub fn rust_0_8_X509_clone(x509: *mut ffi::X509);
    pub fn rust_0_8_X509_get_extensions(x: *mut ffi::X509) -> *mut ffi::stack_st_X509_EXTENSION;
    pub fn rust_0_8_X509_get_notAfter(x: *mut ffi::X509) -> *mut ffi::ASN1_TIME;
    pub fn rust_0_8_X509_get_notBefore(x: *mut ffi::X509) -> *mut ffi::ASN1_TIME;
    pub fn rust_0_8_HMAC_Init_ex(ctx: *mut ffi::HMAC_CTX, key: *const c_void, keylen: c_int, md: *const ffi::EVP_MD, impl_: *mut ffi::ENGINE) -> c_int;
    pub fn rust_0_8_HMAC_Final(ctx: *mut ffi::HMAC_CTX, output: *mut c_uchar, len: *mut c_uint) -> c_int;
    pub fn rust_0_8_HMAC_Update(ctx: *mut ffi::HMAC_CTX, input: *const c_uchar, len: c_uint) -> c_int;
    pub fn rust_0_8_DH_new_from_params(p: *mut ffi::BIGNUM, g: *mut ffi::BIGNUM, q: *mut ffi::BIGNUM) -> *mut ffi::DH;
}
