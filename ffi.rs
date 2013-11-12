#[doc(hidden)];

use std::libc::{c_int, c_void, c_long, c_ulong, c_char};

// openssl/ssl.h
pub type SSL_CTX = c_void;
pub type SSL_METHOD = c_void;
pub type SSL = c_void;
pub type BIO = c_void;
pub type BIO_METHOD = c_void;
pub type X509_STORE_CTX = c_void;
pub type CRYPTO_EX_DATA = c_void;

pub type CRYPTO_EX_new = extern "C" fn(parent: *c_void, ptr: *c_void,
                                       ad: *CRYPTO_EX_DATA, idx: c_int,
                                       argl: c_long, argp: *c_void) -> c_int;
pub type CRYPTO_EX_dup = extern "C" fn(to: *CRYPTO_EX_DATA,
                                       from: *CRYPTO_EX_DATA, from_d: *c_void,
                                       idx: c_int, argl: c_long, argp: *c_void)
                                       -> c_int;
pub type CRYPTO_EX_free = extern "C" fn(parent: *c_void, ptr: *c_void,
                                        ad: *CRYPTO_EX_DATA, idx: c_int,
                                        argl: c_long, argp: *c_void);

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

#[link_args = "-lssl -lcrypto"]
extern "C" {
    pub fn ERR_get_error() -> c_ulong;

    pub fn SSL_library_init() -> c_int;

    pub fn SSLv3_method() -> *SSL_METHOD;
    pub fn TLSv1_method() -> *SSL_METHOD;
    pub fn SSLv23_method() -> *SSL_METHOD;

    pub fn SSL_CTX_new(method: *SSL_METHOD) -> *SSL_CTX;
    pub fn SSL_CTX_free(ctx: *SSL_CTX);
    pub fn SSL_CTX_set_verify(ctx: *SSL_CTX, mode: c_int,
                              verify_callback: Option<extern "C" fn(c_int, *X509_STORE_CTX) -> c_int>);
    pub fn SSL_CTX_load_verify_locations(ctx: *SSL_CTX, CAfile: *c_char,
                                               CApath: *c_char) -> c_int;
    pub fn SSL_CTX_get_ex_new_index(argl: c_long, argp: *c_void,
                                    new_func: Option<CRYPTO_EX_new>,
                                    dup_func: Option<CRYPTO_EX_dup>,
                                    free_func: Option<CRYPTO_EX_free>)
                                    -> c_int;
    pub fn SSL_CTX_set_ex_data(ctx: *SSL_CTX, idx: c_int, data: *c_void)
                               -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *SSL_CTX, idx: c_int) -> *c_void;

    pub fn X509_STORE_CTX_get_ex_data(ctx: *X509_STORE_CTX, idx: c_int)
                                      -> *c_void;

    pub fn SSL_new(ctx: *SSL_CTX) -> *SSL;
    pub fn SSL_free(ssl: *SSL);
    pub fn SSL_set_bio(ssl: *SSL, rbio: *BIO, wbio: *BIO);
    pub fn SSL_get_rbio(ssl: *SSL) -> *BIO;
    pub fn SSL_get_wbio(ssl: *SSL) -> *BIO;
    pub fn SSL_set_connect_state(ssl: *SSL);
    pub fn SSL_connect(ssl: *SSL) -> c_int;
    pub fn SSL_get_error(ssl: *SSL, ret: c_int) -> c_int;
    pub fn SSL_read(ssl: *SSL, buf: *c_void, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *SSL, buf: *c_void, num: c_int) -> c_int;
    pub fn SSL_shutdown(ssl: *SSL) -> c_int;
    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
    pub fn SSL_get_SSL_CTX(ssl: *SSL) -> *SSL_CTX;

    pub fn BIO_s_mem() -> *BIO_METHOD;
    pub fn BIO_new(type_: *BIO_METHOD) -> *BIO;
    pub fn BIO_free_all(a: *BIO);
    pub fn BIO_read(b: *BIO, buf: *c_void, len: c_int) -> c_int;
    pub fn BIO_write(b: *BIO, buf: *c_void, len: c_int) -> c_int;
}
