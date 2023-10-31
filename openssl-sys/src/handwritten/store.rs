
use super::super::*;
use libc::*;

pub enum OSSL_STORE_CTX {}

pub enum OSSL_STORE_INFO {}

pub const OSSL_STORE_INFO_PUBKEY: c_int = 3;
pub const OSSL_STORE_INFO_PKEY: c_int = 4;
pub const OSSL_STORE_INFO_CERT: c_int = 5;
pub const OSSL_STORE_INFO_CRL: c_int = 6;

extern "C" {
    pub fn OSSL_STORE_open(
        uri: *const c_char,
        // const UI_METHOD *ui_method,
        ui_method: *const c_void,
        ui_data: *const c_void,
        // OSSL_STORE_post_process_info_fn post_process,
        post_process: *const c_void,
        post_process_data: *const c_void,
    ) -> *mut OSSL_STORE_CTX;

    pub fn OSSL_STORE_load(ctx: *mut OSSL_STORE_CTX) -> *mut OSSL_STORE_INFO;

    pub fn OSSL_STORE_INFO_get_type(store_info: *mut OSSL_STORE_INFO) -> c_int;

    pub fn OSSL_STORE_INFO_get1_PUBKEY(store_info: *mut OSSL_STORE_INFO) -> *mut EVP_PKEY;

    pub fn OSSL_STORE_INFO_get1_PKEY(store_info: *mut OSSL_STORE_INFO) -> *mut EVP_PKEY;

    pub fn OSSL_STORE_INFO_free(store_info: *mut OSSL_STORE_INFO);

    pub fn OSSL_STORE_close(ctx: *mut OSSL_STORE_CTX) -> c_int;
}
