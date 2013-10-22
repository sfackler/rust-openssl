use std::libc::c_ulong;

use super::ffi;

pub enum SslError {
    StreamEof,
    SslSessionClosed,
    UnknownError(c_ulong)
}

impl SslError {
    pub fn get() -> Option<SslError> {
        match unsafe { ffi::ERR_get_error() } {
            0 => None,
            err => Some(UnknownError(err))
        }
    }
}
