use std::libc::c_ulong;
use std::io::IoError;
use std::vec_ng::Vec;

use ssl::ffi;

/// An SSL error
#[deriving(Show)]
pub enum SslError {
    /// The underlying stream has reported an error
    StreamError(IoError),
    /// The SSL session has been closed by the other end
    SslSessionClosed,
    /// An error in the OpenSSL library
    OpenSslErrors(Vec<OpensslError>)
}

/// An error from the OpenSSL library
#[deriving(Show)]
pub enum OpensslError {
    /// An unknown error
    UnknownError {
        /// The library reporting the error
        library: u8,
        /// The function reporting the error
        function: u16,
        /// The reason for the error
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
    /// Creates a new `OpenSslErrors` with the current contents of the error
    /// stack.
    pub fn get() -> SslError {
        let mut errs = vec!();
        loop {
            match unsafe { ffi::ERR_get_error() } {
                0 => break,
                err => errs.push(UnknownError {
                    library: get_lib(err),
                    function: get_func(err),
                    reason: get_reason(err)
                })
            }
        }
        OpenSslErrors(errs)
    }
}
