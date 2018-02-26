use libc::{c_int, c_ulong};

use ossl110::*;

pub const SSL_COOKIE_LENGTH: c_int = 255;

pub const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: c_ulong = 0x00100000;

extern "C" {
    pub fn SSL_stateless(s: *mut SSL) -> c_int;
}
