use std::libc::{c_int, c_void};

pub type SSL_CTX = c_void;
pub type SSL_METHOD = c_void;

#[link_args = "-lssl"]
extern "C" {
    fn SSL_library_init() -> c_int;
    fn SSL_load_error_strings();

    fn SSL_CTX_new(method: *SSL_METHOD) -> *SSL_CTX;
    fn SSLv23_method() -> *SSL_METHOD;
    fn SSL_CTX_free(ctx: *SSL_CTX);
}
