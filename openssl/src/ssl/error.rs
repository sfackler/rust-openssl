use std::error;
use std::error::Error as StdError;
use std::fmt;
use std::io;
use error::ErrorStack;

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
    Ssl(ErrorStack),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(err) = self.cause() {
            write!(fmt, ": {}", err)
        } else {
            Ok(())
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
            Error::Ssl(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::Ssl(e)
    }
}
