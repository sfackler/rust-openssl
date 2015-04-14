use libc::{c_int};
use std::ffi::{CStr};
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::os::unix::io::RawFd;
use std::net;
use std::ptr;
use std::sync::{Arc};
#[cfg(feature = "npn")]
use libc::{c_uchar, c_uint};
#[cfg(feature = "npn")]
use std::slice;

use bio::{MemBio,SocketBio,Bio};
use ffi;

use super::error::{SslError, SslSessionClosed, StreamError, OpenSslErrors};
use super::{Ssl, SslContext, LibSslError};

pub struct SocketIo;

pub struct StreamIo<S:Read+Write> {
    stream: S,
    buf: Vec<u8>,
}

/// A stream wrapper which handles SSL encryption for an underlying stream.
#[derive(Clone)]
pub struct SslStream<I> {
    io: I,
    pub ssl: Arc<Ssl>,
}

impl<S:Read+Write> StreamIo<S> {
    pub fn new(stream: S) -> StreamIo<S> {
        StreamIo {
            stream: stream,
            // Maximum TLS record size is 16k
            // We're just using this as a buffer, so there's no reason to pay
            // to memset it
            buf: {
                const CAP: usize = 16 * 1024;
                let mut v = Vec::with_capacity(CAP);
                unsafe { v.set_len(CAP); }
                v
            }
        }
    }

    fn write_through(&mut self, ssl: &Arc<Ssl>) -> io::Result<()> {
        io::copy(&mut *ssl.get_wbio::<MemBio>(), &mut self.stream).map(|_| ())
    }
}

impl SslStream<StreamIo<net::TcpStream>> {
    /// Create a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> io::Result<SslStream<StreamIo<net::TcpStream>>> {
        Ok(SslStream { 
            io: StreamIo {
                stream: try!(self.io.stream.try_clone()),
                buf: self.io.buf.clone(),
            },
            ssl: self.ssl.clone(),
        })
    }
}

impl<S> fmt::Debug for SslStream<StreamIo<S>> where S: fmt::Debug+Read+Write {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslStream {{ stream: {:?}, ssl: {:?} }}", self.io.stream, self.ssl)
    }
}

impl fmt::Debug for SslStream<SocketIo> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslStream {{ ssl: {:?} }}", self.ssl)
    }
}

impl<I> SslStream<I> {
    fn new_base(ssl:Ssl, io: I) -> SslStream<I> {
        SslStream {
            io: io,
            ssl: Arc::new(ssl),
        }
    }

    /// Get the compression currently in use.  The result will be
    /// either None, indicating no compression is in use, or a string
    /// with the compression name.
    pub fn get_compression(&self) -> Option<String> {
        let ptr = unsafe { ffi::SSL_get_current_compression(self.ssl.ssl) };
        if ptr == ptr::null() {
            return None;
        }

        let meth = unsafe { ffi::SSL_COMP_get_name(ptr) };
        let s = unsafe {
            String::from_utf8(CStr::from_ptr(meth).to_bytes().to_vec()).unwrap()
        };

        Some(s)
    }

    /// Returns the protocol selected by performing Next Protocol Negotiation, if any.
    ///
    /// The protocol's name is returned is an opaque sequence of bytes. It is up to the client
    /// to interpret it.
    ///
    /// This method needs the `npn` feature.
    #[cfg(feature = "npn")]
    pub fn get_selected_npn_protocol(&self) -> Option<&[u8]> {
        self.ssl.get_selected_npn_protocol()
    }
}

impl SslStream<SocketIo> {
    pub fn new_server_from_socket_from(ssl: Ssl) -> Result<SslStream<SocketIo>, SslError> {
        let mut s = SslStream::new_base(ssl, SocketIo);
        s.in_retry_wrapper(|ssl| { ssl.accept() }).and(Ok(s))
    }

    /// Attempts to create a new SSL stream from a given `Ssl` instance.
    pub fn new_from_socket_from(ssl: Ssl) -> Result<SslStream<SocketIo>, SslError> {
        let mut s = SslStream::new_base(ssl, SocketIo);
        s.in_retry_wrapper(|ssl| { ssl.connect() }).and(Ok(s))
    }

    /// Creates a new SSL stream
    pub fn new_from_socket(ctx: &SslContext, socket: RawFd) -> Result<SslStream<SocketIo>, SslError> {
        let ssl = try!(Ssl::new_from_socket(ctx, socket));
        SslStream::new_from_socket_from(ssl)
    }

    /// Creates a new SSL server stream
    pub fn new_server_from_socket(ctx: &SslContext, socket: RawFd) -> Result<SslStream<SocketIo>, SslError> {
        let ssl = try!(Ssl::new_from_socket(ctx, socket));
        SslStream::new_server_from_socket_from(ssl)
    }

    fn in_retry_wrapper<F>(&mut self, mut blk: F)
            -> Result<c_int, SslError> where F: FnMut(&Arc<Ssl>) -> c_int
    {
        loop {
            let ret = blk(&self.ssl);
            if ret > 0 {
                return Ok(ret);
            } else {
                let e = self.ssl.get_error(ret);
                match e {
                    LibSslError::ErrorWantRead => return Ok(0),
                    LibSslError::ErrorWantWrite => { try_ssl_stream!(self.flush()) }
                    LibSslError::ErrorZeroReturn => return Err(SslSessionClosed),
                    LibSslError::ErrorSsl => return Err(SslError::get()),
                    err => panic!("unexpected error {:?} {:?}", err, io::Error::last_os_error()),
                }
            }
        }
    }
}

impl<S:Read+Write> SslStream<StreamIo<S>> {
    pub fn new_server_from(ssl: Ssl, stream: S) -> Result<SslStream<StreamIo<S>>, SslError> {
        let mut s = SslStream::new_base(ssl, StreamIo::new(stream));
        s.in_retry_wrapper(|ssl| { ssl.accept() }).and(Ok(s))
    }

    /// Attempts to create a new SSL stream from a given `Ssl` instance.
    pub fn new_from(ssl: Ssl, stream: S) -> Result<SslStream<StreamIo<S>>, SslError> {
        let mut s = SslStream::new_base(ssl, StreamIo::new(stream));
        s.in_retry_wrapper(|ssl| { ssl.connect() }).and(Ok(s))
    }

    /// Creates a new SSL stream
    pub fn new(ctx: &SslContext, stream: S) -> Result<SslStream<StreamIo<S>>, SslError> {
        let ssl = try!(Ssl::new(ctx));
        SslStream::new_from(ssl, stream)
    }

    /// Creates a new SSL server stream
    pub fn new_server(ctx: &SslContext, stream: S) -> Result<SslStream<StreamIo<S>>, SslError> {
        let ssl = try!(Ssl::new(ctx));
        SslStream::new_server_from(ssl, stream)
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// `read`ing or `write`ing directly to the underlying stream will most
    /// likely desynchronize the SSL session.
    #[deprecated="use get_mut instead"]
    pub fn get_inner(&mut self) -> &mut S {
        self.get_mut()
    }

    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.io.stream
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely desynchronize the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io.stream
    }

    fn in_retry_wrapper<F>(&mut self, mut blk: F)
            -> Result<c_int, SslError> where F: FnMut(&Arc<Ssl>) -> c_int {
        loop {
            let ret = blk(&self.ssl);
            if ret > 0 {
                return Ok(ret);
            }

            let e = self.ssl.get_error(ret);
            match e {
                LibSslError::ErrorWantRead => {
                    try_ssl_stream!(self.flush());
                    let len = try_ssl_stream!(self.io.stream.read(&mut self.io.buf[..]));
                    if len == 0 {
                        return Ok(0);
                    }
                    try_ssl_stream!(self.ssl.get_rbio::<MemBio>().write_all(&self.io.buf[..len]));
                }
                LibSslError::ErrorWantWrite => { try_ssl_stream!(self.flush()) }
                LibSslError::ErrorZeroReturn => return Err(SslSessionClosed),
                LibSslError::ErrorSsl => return Err(SslError::get()),
                err => panic!("unexpected error {:?} {:?}", err, io::Error::last_os_error()),
            }
        }
    }
}

impl Read for SslStream<SocketIo> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Ok(len as usize),
            Err(SslSessionClosed) => Ok(0),
            Err(StreamError(e)) => Err(e),
            Err(e @ OpenSslErrors(_)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

impl Write for SslStream<SocketIo> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.in_retry_wrapper(|ssl| ssl.write(buf)) {
            Ok(len) => Ok(len as usize),
            Err(SslSessionClosed) => Ok(0),
            Err(StreamError(e)) => return Err(e),
            Err(e @ OpenSslErrors(_)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.ssl.get_rbio::<SocketBio>().flush() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "SocketBio::flush() failed"))
        }
    }
}

impl<S: Read+Write> Read for SslStream<StreamIo<S>> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Ok(len as usize),
            Err(SslSessionClosed) => Ok(0),
            Err(StreamError(e)) => Err(e),
            Err(e @ OpenSslErrors(_)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

impl<S:Read+Write> Write for SslStream<StreamIo<S>> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.in_retry_wrapper(|ssl| ssl.write(buf)) {
            Ok(len) => Ok(len as usize),
            Err(SslSessionClosed) => Ok(0),
            Err(StreamError(e)) => return Err(e),
            Err(e @ OpenSslErrors(_)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        try!(self.io.write_through(&self.ssl));
        self.io.stream.flush()
    }
}

/// A utility type to help in cases where the use of SSL is decided at runtime.
#[derive(Debug)]
pub enum MaybeSslStream<S> where S: Read+Write {
    /// A connection using SSL
    Ssl(SslStream<StreamIo<S>>),
    /// A connection not using SSL
    Normal(S),
}

impl<S> Read for MaybeSslStream<S> where S: Read+Write {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.read(buf),
            MaybeSslStream::Normal(ref mut s) => s.read(buf),
        }
    }
}

impl<S> Write for MaybeSslStream<S> where S: Read+Write {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.write(buf),
            MaybeSslStream::Normal(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.flush(),
            MaybeSslStream::Normal(ref mut s) => s.flush(),
        }
    }
}

impl<S> MaybeSslStream<S> where S: Read+Write {
    /// Returns a reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        match *self {
            MaybeSslStream::Ssl(ref s) => s.get_ref(),
            MaybeSslStream::Normal(ref s) => s,
        }
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// ## Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        match *self {
            MaybeSslStream::Ssl(ref mut s) => s.get_mut(),
            MaybeSslStream::Normal(ref mut s) => s,
        }
    }
}
