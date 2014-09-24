use libc::c_ulong;
use std::io::IoError;
use std::c_str::CString;

use ssl::ffi;

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
        library: u8,
        /// The function reporting the error
        function: u16,
        /// The reason for the error
        reason: u16,

        library_str: Option<CString>,
        function_str: Option<CString>,
        reason_str: Option<CString>
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

fn get_lib_str(err: c_ulong) -> Option<CString> {
    unsafe {
        let ptr = ffi::ERR_lib_error_string(err);
        if ptr.is_null() {
            None
        } else {
            Some(CString::new(ptr, false))
        }
    }
}

fn get_func_str(err: c_ulong) -> Option<CString> {
    unsafe {
        let ptr = ffi::ERR_func_error_string(err);
        if ptr.is_null() {
            None
        } else {
            Some(CString::new(ptr, false))
        }
    }
}

fn get_reason_str(err: c_ulong) -> Option<CString> {
    unsafe {
        let ptr = ffi::ERR_reason_error_string(err);
        if ptr.is_null() {
            None
        } else {
            Some(CString::new(ptr, false))
        }
    }
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
                    reason: get_reason(err),
                    library_str: get_lib_str(err),
                    function_str: get_func_str(err),
                    reason_str: get_reason_str(err),
                })
            }
        }
        OpenSslErrors(errs)
    }
}
