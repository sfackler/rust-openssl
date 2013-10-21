#[doc(hidden)];

use std::libc::{c_int, c_void, c_ulong, c_char};

// openssl/ssl.h
pub type SSL_CTX = c_void;
pub type SSL_METHOD = c_void;
pub type SSL = c_void;
pub type BIO = c_void;
pub type BIO_METHOD = c_void;
pub type X509_STORE_CTX = c_void;

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

#[link_args = "-lssl"]
extern "C" { }

externfn!(fn ERR_get_error() -> c_ulong)

externfn!(fn SSL_library_init() -> c_int)

externfn!(fn SSLv23_method() -> *SSL_METHOD)
externfn!(fn SSL_CTX_new(method: *SSL_METHOD) -> *SSL_CTX)
externfn!(fn SSL_CTX_free(ctx: *SSL_CTX))
externfn!(fn SSL_CTX_set_verify(ctx: *SSL_CTX, mode: c_int,
                                verify_callback: Option<extern "C" fn(int, *X509_STORE_CTX) -> c_int>))
externfn!(fn SSL_CTX_load_verify_locations(ctx: *SSL_CTX, CAfile: *c_char,
                                           CApath: *c_char) -> c_int)

externfn!(fn SSL_new(ctx: *SSL_CTX) -> *SSL)
externfn!(fn SSL_free(ssl: *SSL))
externfn!(fn SSL_set_bio(ssl: *SSL, rbio: *BIO, wbio: *BIO))
externfn!(fn SSL_set_connect_state(ssl: *SSL))
externfn!(fn SSL_connect(ssl: *SSL) -> c_int)
externfn!(fn SSL_get_error(ssl: *SSL, ret: c_int) -> c_int)
externfn!(fn SSL_read(ssl: *SSL, buf: *c_void, num: c_int) -> c_int)
externfn!(fn SSL_write(ssl: *SSL, buf: *c_void, num: c_int) -> c_int)
externfn!(fn SSL_shutdown(ssl: *SSL) -> c_int)

externfn!(fn BIO_s_mem() -> *BIO_METHOD)
externfn!(fn BIO_new(type_: *BIO_METHOD) -> *BIO)
externfn!(fn BIO_read(b: *BIO, buf: *c_void, len: c_int) -> c_int)
externfn!(fn BIO_write(b: *BIO, buf: *c_void, len: c_int) -> c_int)
