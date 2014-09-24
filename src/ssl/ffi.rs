#![allow(non_camel_case_types)]

use libc::{c_int, c_void, c_long, c_ulong, c_char};

use bio;
use x509;

pub type SSL_CTX = c_void;
pub type SSL_METHOD = c_void;
pub type COMP_METHOD = c_void;
pub type SSL = c_void;
pub type CRYPTO_EX_DATA = c_void;

pub type CRYPTO_EX_new = extern "C" fn(parent: *mut c_void, ptr: *mut c_void,
                                       ad: *const CRYPTO_EX_DATA, idx: c_int,
                                       argl: c_long, argp: *const c_void) -> c_int;
pub type CRYPTO_EX_dup = extern "C" fn(to: *mut CRYPTO_EX_DATA,
                                       from: *mut CRYPTO_EX_DATA, from_d: *mut c_void,
                                       idx: c_int, argl: c_long, argp: *mut c_void)
                                       -> c_int;
pub type CRYPTO_EX_free = extern "C" fn(parent: *mut c_void, ptr: *mut c_void,
                                        ad: *mut CRYPTO_EX_DATA, idx: c_int,
                                        argl: c_long, argp: *mut c_void);

pub static CRYPTO_LOCK: c_int = 1;

pub static SSL_ERROR_NONE: c_int = 0;
pub static SSL_ERROR_SSL: c_int = 1;
pub static SSL_ERROR_WANT_READ: c_int = 2;
pub static SSL_ERROR_WANT_WRITE: c_int = 3;
pub static SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub static SSL_ERROR_SYSCALL: c_int = 5;
pub static SSL_ERROR_ZERO_RETURN: c_int = 6;
pub static SSL_ERROR_WANT_CONNECT: c_int = 7;
pub static SSL_ERROR_WANT_ACCEPT: c_int = 8;

pub static SSL_VERIFY_NONE: c_int = 0;
pub static SSL_VERIFY_PEER: c_int = 1;

pub static SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;

pub static TLSEXT_NAMETYPE_host_name: c_long = 0;


#[cfg(target_os = "macos", feature = "tlsv1_1")]
#[cfg(target_os = "macos", feature = "tlsv1_2")]
#[link(name="ssl.1.0.0")]
#[link(name="crypto.1.0.0")]
extern {}

#[cfg(not(target_os = "macos"))]
#[cfg(target_os = "macos", not(feature = "tlsv1_1"), not(feature = "tlsv1_2"))]
#[link(name="ssl")]
#[link(name="crypto")]
extern {}

extern "C" {
    pub fn CRYPTO_num_locks() -> c_int;
    pub fn CRYPTO_set_locking_callback(func: extern "C" fn(mode: c_int,
                                                           n: c_int,
                                                           file: *const c_char,
                                                           line: c_int));

    pub fn ERR_get_error() -> c_ulong;

    pub fn SSL_library_init() -> c_int;

    #[cfg(feature = "sslv2")]
    pub fn SSLv2_method() -> *const SSL_METHOD;
    pub fn SSLv3_method() -> *const SSL_METHOD;
    pub fn TLSv1_method() -> *const SSL_METHOD;
    #[cfg(feature = "tlsv1_1")]
    pub fn TLSv1_1_method() -> *const SSL_METHOD;
    #[cfg(feature = "tlsv1_2")]
    pub fn TLSv1_2_method() -> *const SSL_METHOD;
    pub fn SSLv23_method() -> *const SSL_METHOD;

    pub fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);
    pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int,
                              verify_callback: Option<extern fn(c_int, *mut x509::ffi::X509_STORE_CTX) -> c_int>);
    pub fn SSL_CTX_load_verify_locations(ctx: *mut SSL_CTX, CAfile: *const c_char,
                                         CApath: *const c_char) -> c_int;
    pub fn SSL_CTX_get_ex_new_index(argl: c_long, argp: *const c_void,
                                    new_func: Option<CRYPTO_EX_new>,
                                    dup_func: Option<CRYPTO_EX_dup>,
                                    free_func: Option<CRYPTO_EX_free>)
                                    -> c_int;
    pub fn SSL_CTX_set_ex_data(ctx: *mut SSL_CTX, idx: c_int, data: *mut c_void)
                               -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *mut SSL_CTX, idx: c_int) -> *mut c_void;

    pub fn SSL_CTX_use_certificate_file(ctx: *mut SSL_CTX, cert_file: *const c_char, file_type: c_int) -> c_int;
    pub fn SSL_CTX_use_PrivateKey_file(ctx: *mut SSL_CTX, key_file: *const c_char, file_type: c_int) -> c_int;

    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    pub fn SSL_free(ssl: *mut SSL);
    pub fn SSL_set_bio(ssl: *mut SSL, rbio: *mut bio::ffi::BIO, wbio: *mut bio::ffi::BIO);
    pub fn SSL_get_rbio(ssl: *mut SSL) -> *mut bio::ffi::BIO;
    pub fn SSL_get_wbio(ssl: *mut SSL) -> *mut bio::ffi::BIO;
    pub fn SSL_connect(ssl: *mut SSL) -> c_int;
    pub fn SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long,
                    parg: *mut c_void) -> c_long;
    pub fn SSL_get_error(ssl: *mut SSL, ret: c_int) -> c_int;
    pub fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
    pub fn SSL_get_SSL_CTX(ssl: *mut SSL) -> *mut SSL_CTX;
    pub fn SSL_get_current_compression(ssl: *mut SSL) -> *const COMP_METHOD;

    pub fn SSL_COMP_get_name(comp: *const COMP_METHOD) -> *const c_char;
}

#[cfg(target_os = "win32")]
#[link(name="gdi32")]
#[link(name="wsock32")]
extern { }
