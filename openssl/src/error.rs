use libc::c_ulong;
use std::fmt;
use std::error;
use std::ffi::CStr;
use std::io;
use std::str;

use ffi;

#[derive(Debug, Clone)]
pub struct ErrorStack(Vec<Error>);

impl ErrorStack {
    /// Returns the contents of the OpenSSL error stack.
    pub fn get() -> ErrorStack {
        let mut vec = vec![];
        while let Some(err) = Error::get() {
            vec.push(err);
        }
        ErrorStack(vec)
    }
}

impl ErrorStack {
    /// Returns the errors in the stack.
    pub fn errors(&self) -> &[Error] {
        &self.0
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for err in &self.0 {
            if first {
                try!(fmt.write_str(", "));
                first = false;
            }
            try!(write!(fmt, "{}", err));
        }
        Ok(())
    }
}

impl error::Error for ErrorStack {
    fn description(&self) -> &str {
        "An OpenSSL error stack"
    }
}

impl From<ErrorStack> for io::Error {
    fn from(e: ErrorStack) -> io::Error {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

impl From<ErrorStack> for fmt::Error {
    fn from(_: ErrorStack) -> fmt::Error {
        fmt::Error
    }
}

/// An error reported from OpenSSL.
#[derive(Clone)]
pub struct Error(c_ulong);

impl Error {
    /// Returns the first error on the OpenSSL error stack.
    pub fn get() -> Option<Error> {
        ffi::init();

        match unsafe { ffi::ERR_get_error() } {
            0 => None,
            err => Some(Error(err)),
        }
    }

    /// Returns the raw OpenSSL error code for this error.
    pub fn error_code(&self) -> c_ulong {
        self.0
    }

    /// Returns the name of the library reporting the error.
    pub fn library(&self) -> &'static str {
        get_lib(self.0)
    }

    /// Returns the name of the function reporting the error.
    pub fn function(&self) -> &'static str {
        get_func(self.0)
    }

    /// Returns the reason for the error.
    pub fn reason(&self) -> &'static str {
        get_reason(self.0)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Error")
           .field("library", &self.library())
           .field("function", &self.function())
           .field("reason", &self.reason())
           .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&self.reason())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "An OpenSSL error"
    }
}

fn get_lib(err: c_ulong) -> &'static str {
    unsafe {
        let cstr = ffi::ERR_lib_error_string(err);
        assert!(!cstr.is_null(), "bad lib: {}", err);
        let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
        str::from_utf8(bytes).unwrap()
    }
}

fn get_func(err: c_ulong) -> &'static str {
    unsafe {
        let cstr = ffi::ERR_func_error_string(err);
        assert!(!cstr.is_null(), "bad func: {}", err);
        let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
        str::from_utf8(bytes).unwrap()
    }
}

fn get_reason(err: c_ulong) -> &'static str {
    unsafe {
        let cstr = ffi::ERR_reason_error_string(err);
        assert!(!cstr.is_null(), "bad reason: {}", err);
        let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
        str::from_utf8(bytes).unwrap()
    }
}

