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
            if !first {
                try!(fmt.write_str(", "));
            }
            try!(write!(fmt, "{}", err));
            first = false;
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
    pub fn code(&self) -> c_ulong {
        self.0
    }

    /// Returns the name of the library reporting the error, if available.
    pub fn library(&self) -> Option<&'static str> {
        unsafe {
            let cstr = ffi::ERR_lib_error_string(self.0);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    /// Returns the name of the function reporting the error.
    pub fn function(&self) -> Option<&'static str> {
        unsafe {
            let cstr = ffi::ERR_func_error_string(self.0);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    /// Returns the reason for the error.
    pub fn reason(&self) -> Option<&'static str> {
        unsafe {
            let cstr = ffi::ERR_reason_error_string(self.0);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.code());
        if let Some(library) = self.library() {
            builder.field("library", &library);
        }
        if let Some(function) = self.function() {
            builder.field("function", &function);
        }
        if let Some(reason) = self.reason() {
            builder.field("reason", &reason);
        }
        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "error:{:08X}", self.0));
        match self.library() {
            Some(l) => try!(write!(fmt, ":{}", l)),
            None => try!(write!(fmt, ":lib({})", ffi::ERR_GET_LIB(self.0))),
        }
        match self.function() {
            Some(f) => try!(write!(fmt, ":{}", f)),
            None => try!(write!(fmt, ":func({})", ffi::ERR_GET_FUNC(self.0))),
        }
        match self.reason() {
            Some(r) => write!(fmt, ":{}", r),
            None => write!(fmt, ":reason({})", ffi::ERR_GET_FUNC(self.0)),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "An OpenSSL error"
    }
}
