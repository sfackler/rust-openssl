use libc::c_ulong;
use std::io::IoError;
use std::c_str::CString;

use ffi;

/// An SSL error
#[deriving(Show, Clone, PartialEq, Eq)]
pub enum SslError {
    /// The underlying stream has reported an error
    StreamError(IoError),
    /// The SSL session has been closed by the other end
    SslSessionClosed,
    /// An error in the OpenSSL library
    OpenSslErrors(Vec<OpensslError>)
}

/// An error from the OpenSSL library
#[deriving(Show, Clone, PartialEq, Eq)]
pub enum OpensslError {
    /// An unknown error
    UnknownError {
        /// The library reporting the error
        library: CString,
        /// The function reporting the error
        function: CString,
        /// The reason for the error
        reason: CString
    }
}

fn get_lib(err: c_ulong) -> CString {
    unsafe { CString::new(ffi::ERR_lib_error_string(err), false) }
}

fn get_func(err: c_ulong) -> CString {
    unsafe { CString::new(ffi::ERR_func_error_string(err), false) }
}

fn get_reason(err: c_ulong) -> CString {
    unsafe { CString::new(ffi::ERR_reason_error_string(err), false) }
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
