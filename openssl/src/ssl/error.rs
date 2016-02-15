pub use self::SslError::*;
pub use self::OpensslError::*;

use libc::c_ulong;
use std::error;
use std::error::Error as StdError;
use std::fmt;
use std::ffi::CStr;
use std::io;
use std::str;

use ffi;

/// An SSL error.
#[derive(Debug)]
pub enum Error {
    /// The SSL session has been closed by the other end
    ZeroReturn,
    /// An attempt to read data from the underlying socket returned
    /// `WouldBlock`. Wait for read readiness and reattempt the operation.
    WantRead(io::Error),
    /// An attempt to write data from the underlying socket returned
    /// `WouldBlock`. Wait for write readiness and reattempt the operation.
    WantWrite(io::Error),
    /// The client certificate callback requested to be called again.
    WantX509Lookup,
    /// An error reported by the underlying stream.
    Stream(io::Error),
    /// An error in the OpenSSL library.
    Ssl(Vec<OpenSslError>),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        match *self {
            Error::Stream(ref err) => write!(fmt, ": {}", err),
            Error::WantRead(ref err) => write!(fmt, ": {}", err),
            Error::WantWrite(ref err) => write!(fmt, ": {}", err),
            Error::Ssl(ref errs) => {
                let mut first = true;
                for err in errs {
                    if first {
                        try!(fmt.write_str(": "));
                        first = false;
                    } else {
                        try!(fmt.write_str(", "));
                    }
                    try!(fmt.write_str(&err.reason()))
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ZeroReturn => "The SSL session was closed by the other end",
            Error::WantRead(_) => "A read attempt returned a `WouldBlock` error",
            Error::WantWrite(_) => "A write attempt returned a `WouldBlock` error",
            Error::WantX509Lookup => "The client certificate callback requested to be called again",
            Error::Stream(_) => "The underlying stream reported an error",
            Error::Ssl(_) => "The OpenSSL library reported an error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::WantRead(ref err) => Some(err),
            Error::WantWrite(ref err) => Some(err),
            Error::Stream(ref err) => Some(err),
            _ => None,
        }
    }
}

/// An error reported from OpenSSL.
pub struct OpenSslError(c_ulong);

impl OpenSslError {
    /// Returns the contents of the OpenSSL error stack.
    pub fn get_stack() -> Vec<OpenSslError> {
        ffi::init();

        let mut errs = vec![];
        loop {
            match unsafe { ffi::ERR_get_error() } {
                0 => break,
                err => errs.push(OpenSslError(err)),
            }
        }
        errs
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

impl fmt::Debug for OpenSslError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("OpenSslError")
           .field("library", &self.library())
           .field("function", &self.function())
           .field("reason", &self.reason())
           .finish()
    }
}

impl fmt::Display for OpenSslError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&self.reason())
    }
}

impl error::Error for OpenSslError {
    fn description(&self) -> &str {
        "An OpenSSL error"
    }
}

/// An SSL error
#[derive(Debug)]
pub enum SslError {
    /// The underlying stream reported an error
    StreamError(io::Error),
    /// The SSL session has been closed by the other end
    SslSessionClosed,
    /// An error in the OpenSSL library
    OpenSslErrors(Vec<OpensslError>),
}

/// An error on a nonblocking stream.
#[derive(Debug)]
pub enum NonblockingSslError {
    /// A standard SSL error occurred.
    SslError(SslError),
    /// The OpenSSL library wants data from the remote socket;
    /// the caller should wait for read readiness.
    WantRead,
    /// The OpenSSL library wants to send data to the remote socket;
    /// the caller should wait for write readiness.
    WantWrite,
}

impl fmt::Display for SslError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(error::Error::description(self)));
        if let OpenSslErrors(ref errs) = *self {
            let mut first = true;
            for err in errs {
                if first {
                    try!(fmt.write_str(": "));
                    first = false;
                } else {
                    try!(fmt.write_str(", "));
                }
                match *err {
                    UnknownError { ref reason, .. } => try!(fmt.write_str(reason)),
                }
            }
        }

        Ok(())
    }
}

impl error::Error for SslError {
    fn description(&self) -> &str {
        match *self {
            StreamError(_) => "The underlying stream reported an error",
            SslSessionClosed => "The SSL session has been closed by the other end",
            OpenSslErrors(_) => "An error in the OpenSSL library",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            StreamError(ref err) => Some(err as &error::Error),
            _ => None,
        }
    }
}

impl fmt::Display for NonblockingSslError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(error::Error::description(self))
    }
}

impl error::Error for NonblockingSslError {
    fn description(&self) -> &str {
        match *self {
            NonblockingSslError::SslError(ref e) => e.description(),
            NonblockingSslError::WantRead => {
                "The OpenSSL library wants data from the remote socket"
            }
            NonblockingSslError::WantWrite => {
                "The OpenSSL library want to send data to the remote socket"
            }
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            NonblockingSslError::SslError(ref e) => e.cause(),
            _ => None,
        }
    }
}

impl From<SslError> for NonblockingSslError {
    fn from(e: SslError) -> NonblockingSslError {
        NonblockingSslError::SslError(e)
    }
}

/// An error from the OpenSSL library
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpensslError {
    /// An unknown error
    UnknownError {
        /// The library reporting the error
        library: String,
        /// The function reporting the error
        function: String,
        /// The reason for the error
        reason: String,
    },
}

impl OpensslError {
    pub fn from_error_code(err: c_ulong) -> OpensslError {
        ffi::init();
        UnknownError {
            library: get_lib(err).to_owned(),
            function: get_func(err).to_owned(),
            reason: get_reason(err).to_owned(),
        }
    }
}

fn get_lib(err: c_ulong) -> &'static str {
    unsafe {
        let cstr = ffi::ERR_lib_error_string(err);
        let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
        str::from_utf8(bytes).unwrap()
    }
}

fn get_func(err: c_ulong) -> &'static str {
    unsafe {
        let cstr = ffi::ERR_func_error_string(err);
        let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
        str::from_utf8(bytes).unwrap()
    }
}

fn get_reason(err: c_ulong) -> &'static str {
    unsafe {
        let cstr = ffi::ERR_reason_error_string(err);
        let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
        str::from_utf8(bytes).unwrap()
    }
}

impl SslError {
    /// Creates a new `OpenSslErrors` with the current contents of the error
    /// stack.
    pub fn get() -> SslError {
        let mut errs = vec![];
        loop {
            match unsafe { ffi::ERR_get_error() } {
                0 => break,
                err => errs.push(OpensslError::from_error_code(err)),
            }
        }
        OpenSslErrors(errs)
    }

    /// Creates an `SslError` from the raw numeric error code.
    pub fn from_error(err: c_ulong) -> SslError {
        OpenSslErrors(vec![OpensslError::from_error_code(err)])
    }
}

#[test]
fn test_uknown_error_should_have_correct_messages() {
    let errs = match SslError::from_error(336032784) {
        OpenSslErrors(errs) => errs,
        _ => panic!("This should always be an `OpenSslErrors` variant."),
    };

    let UnknownError { ref library, ref function, ref reason } = errs[0];

    assert_eq!(&library[..], "SSL routines");
    assert_eq!(&function[..], "SSL23_GET_SERVER_HELLO");
    assert_eq!(&reason[..], "sslv3 alert handshake failure");
}
