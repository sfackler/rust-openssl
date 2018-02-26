use libc::{c_char, c_int, c_ulong};

pub type SSL_CTX_keylog_cb_func =
    Option<unsafe extern "C" fn(ssl: *const ::SSL, line: *const c_char)>;

pub const SSL_COOKIE_LENGTH: c_int = 255;

pub const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: c_ulong = 0x00100000;

pub const TLS1_3_VERSION: c_int = 0x304;

extern "C" {
    pub fn SSL_CTX_set_keylog_callback(ctx: *mut ::SSL_CTX, cb: SSL_CTX_keylog_cb_func);
    pub fn SSL_stateless(s: *mut ::SSL) -> c_int;
}
