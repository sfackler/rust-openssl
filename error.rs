use std::libc::c_ulong;

use super::ffi;

#[deriving(ToStr)]
pub enum SslError {
    StreamEof,
    SslSessionClosed,
    UnknownError {
        library: u8,
        function: u16,
        reason: u16
    }
}

fn get_lib(err: c_ulong) -> u8 {
    ((err >> 24) & 0xff) as u8
}

fn get_func(err: c_ulong) -> u16 {
    ((err >> 12) & 0xfff) as u16
}

fn get_reason(err: c_ulong) -> u16 {
    (err & 0xfff) as u16
}

impl SslError {
    pub fn get() -> Option<SslError> {
        match unsafe { ffi::ERR_get_error() } {
            0 => None,
            err => Some(UnknownError {
                library: get_lib(err),
                function: get_func(err),
                reason: get_reason(err)
            })
        }
    }
}
