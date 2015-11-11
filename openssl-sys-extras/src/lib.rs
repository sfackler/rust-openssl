#![allow(non_upper_case_globals, non_snake_case)]

extern crate openssl_sys;
extern crate libc;

use libc::{c_int, c_uint, c_long, c_char};
use openssl_sys::{HMAC_CTX, EVP_MD, ENGINE, SSL_CTX, BIO, X509, stack_st_X509_EXTENSION, SSL, DH};

macro_rules! import_options {
    ( $( $name:ident $val:expr  )* ) => {
       $( pub const $name: u64 = $val; )*
    };
}

include!("ssl_options.rs");

pub unsafe fn SSL_CTX_set_options(ssl: *mut SSL_CTX, op: u64) -> u64 {
    rust_openssl_ssl_ctx_options_c_to_rust(SSL_CTX_set_options_shim(ssl, rust_openssl_ssl_ctx_options_rust_to_c(op)))
}

pub unsafe fn SSL_CTX_get_options(ssl: *mut SSL_CTX) -> u64 {
    rust_openssl_ssl_ctx_options_c_to_rust(SSL_CTX_get_options_shim(ssl))
}

pub unsafe fn SSL_CTX_clear_options(ssl: *mut SSL_CTX, op: u64) -> u64 {
    rust_openssl_ssl_ctx_options_c_to_rust(SSL_CTX_clear_options_shim(ssl, rust_openssl_ssl_ctx_options_rust_to_c(op)))
}

extern {
    fn rust_openssl_ssl_ctx_options_rust_to_c(rustval: u64) -> c_long;
    fn rust_openssl_ssl_ctx_options_c_to_rust(cval: c_long) -> u64;

    // Pre-1.0 versions of these didn't return anything, so the shims bridge that gap
    #[cfg_attr(not(target_os = "nacl"), link_name = "HMAC_Init_ex_shim")]
    pub fn HMAC_Init_ex(ctx: *mut HMAC_CTX, key: *const u8, keylen: c_int, md: *const EVP_MD, imple: *const ENGINE) -> c_int;
    #[cfg_attr(not(target_os = "nacl"), link_name = "HMAC_Final_shim")]
    pub fn HMAC_Final(ctx: *mut HMAC_CTX, output: *mut u8, len: *mut c_uint) -> c_int;
    #[cfg_attr(not(target_os = "nacl"), link_name = "HMAC_Update_shim")]
    pub fn HMAC_Update(ctx: *mut HMAC_CTX, input: *const u8, len: c_uint) -> c_int;

    // These functions are defined in OpenSSL as macros, so we shim them
    #[link_name = "BIO_eof_shim"]
    pub fn BIO_eof(b: *mut BIO) -> c_int;
    #[link_name = "BIO_set_nbio_shim"]
    pub fn BIO_set_nbio(b: *mut BIO, enabled: c_long) -> c_long;
    #[link_name = "BIO_set_mem_eof_return_shim"]
    pub fn BIO_set_mem_eof_return(b: *mut BIO, v: c_int);
    pub fn SSL_CTX_set_options_shim(ctx: *mut SSL_CTX, options: c_long) -> c_long;
    pub fn SSL_CTX_get_options_shim(ctx: *mut SSL_CTX) -> c_long;
    pub fn SSL_CTX_clear_options_shim(ctx: *mut SSL_CTX, options: c_long) -> c_long;
    #[link_name = "SSL_CTX_add_extra_chain_cert_shim"]
    pub fn SSL_CTX_add_extra_chain_cert(ctx: *mut SSL_CTX, x509: *mut X509) -> c_long;
    #[link_name = "SSL_CTX_set_read_ahead_shim"]
    pub fn SSL_CTX_set_read_ahead(ctx: *mut SSL_CTX, m: c_long) -> c_long;
    #[cfg(feature = "ecdh_auto")]
    #[link_name = "SSL_CTX_set_ecdh_auto_shim"]
    pub fn SSL_CTX_set_ecdh_auto(ssl: *mut SSL_CTX, onoff: c_int) -> c_int;
    #[link_name = "SSL_set_tlsext_host_name_shim"]
    pub fn SSL_set_tlsext_host_name(s: *mut SSL, name: *const c_char) -> c_long;
    #[link_name = "SSL_CTX_set_tmp_dh_shim"]
    pub fn SSL_CTX_set_tmp_dh(s: *mut SSL, dh: *const DH) -> c_long;
    #[link_name = "X509_get_extensions_shim"]
    pub fn X509_get_extensions(x: *mut X509) -> *mut stack_st_X509_EXTENSION;
}
