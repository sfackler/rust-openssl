#[doc(hidden)];

use std::libc::{c_int, c_void};

pub type SSL_CTX = c_void;
pub type SSL_METHOD = c_void;
pub type SSL = c_void;
pub type BIO = c_void;
pub type BIO_METHOD = c_void;

#[link_args = "-lssl"]
extern "C" { }

externfn!(fn SSL_library_init() -> c_int)
externfn!(fn SSL_load_error_strings())

externfn!(fn SSLv23_method() -> *SSL_METHOD)
externfn!(fn SSL_CTX_new(method: *SSL_METHOD) -> *SSL_CTX)
externfn!(fn SSL_CTX_free(ctx: *SSL_CTX))

externfn!(fn SSL_new(ctx: *SSL_CTX) -> *SSL)
externfn!(fn SSL_free(ssl: *SSL))
externfn!(fn SSL_set_bio(ssl: *SSL, rbio: *BIO, wbio: *BIO))
externfn!(fn SSL_set_connect_state(ssl: *SSL))
externfn!(fn SSL_do_handshake(ssl: *SSL))

externfn!(fn BIO_s_mem() -> *BIO_METHOD)
externfn!(fn BIO_new(type_: *BIO_METHOD) -> *BIO)
externfn!(fn BIO_free(a: *BIO) -> c_int)
