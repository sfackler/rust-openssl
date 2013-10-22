use std::libc::{c_int, c_void};
use std::ptr;
use std::task;
use std::unstable::atomics::{AtomicBool, INIT_ATOMIC_BOOL, Acquire, Release};
use std::rt::io::{Stream, Reader, Writer, Decorator};
use std::vec;

use error::{SslError, SslSessionClosed, StreamEof};

pub mod error;

#[cfg(test)]
mod tests;

mod ffi;

static mut STARTED_INIT: AtomicBool = INIT_ATOMIC_BOOL;
static mut FINISHED_INIT: AtomicBool = INIT_ATOMIC_BOOL;

pub fn init() {
    unsafe {
        if STARTED_INIT.swap(true, Acquire) {
            while !FINISHED_INIT.load(Release) {
                task::deschedule();
            }
            return;
        }

        ffi::SSL_library_init();
        FINISHED_INIT.store(true, Release);
    }
}

pub enum SslMethod {
    Sslv2,
    Sslv3,
    Tlsv1,
    Sslv23
}

impl SslMethod {
    unsafe fn to_raw(&self) -> *ffi::SSL_METHOD {
        match *self {
            Sslv2 => ffi::SSLv2_method(),
            Sslv3 => ffi::SSLv3_method(),
            Tlsv1 => ffi::TLSv1_method(),
            Sslv23 => ffi::SSLv23_method()
        }
    }
}

pub enum SslVerifyMode {
    SslVerifyPeer = ffi::SSL_VERIFY_PEER,
    SslVerifyNone = ffi::SSL_VERIFY_NONE
}

pub struct SslContext {
    priv ctx: *ffi::SSL_CTX
}

impl Drop for SslContext {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx) }
    }
}

impl SslContext {
    pub fn try_new(method: SslMethod) -> Result<SslContext, SslError> {
        init();

        let ctx = unsafe { ffi::SSL_CTX_new(method.to_raw()) };
        if ctx == ptr::null() {
            return Err(SslError::get().unwrap());
        }

        Ok(SslContext { ctx: ctx })
    }

    pub fn new(method: SslMethod) -> SslContext {
        match SslContext::try_new(method) {
            Ok(ctx) => ctx,
            Err(err) => fail!("Error creating SSL context: {:?}", err)
        }
    }

    // TODO: support callback (see SSL_CTX_set_ex_data)
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe {
            ffi::SSL_CTX_set_verify(self.ctx, mode as c_int, None);
        }
    }

    pub fn set_CA_file(&mut self, file: &str) -> Option<SslError> {
        let ret = do file.with_c_str |file| {
            unsafe {
                ffi::SSL_CTX_load_verify_locations(self.ctx, file, ptr::null())
            }
        };

        if ret == 0 {
            Some(SslError::get().unwrap())
        } else {
            None
        }
    }
}

struct Ssl {
    ssl: *ffi::SSL
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl) }
    }
}

impl Ssl {
    fn try_new(ctx: &SslContext) -> Result<Ssl, SslError> {
        let ssl = unsafe { ffi::SSL_new(ctx.ctx) };
        if ssl == ptr::null() {
            return Err(SslError::get().unwrap());
        }
        let ssl = Ssl { ssl: ssl };

        let rbio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        if rbio == ptr::null() {
            return Err(SslError::get().unwrap());
        }

        let wbio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        if wbio == ptr::null() {
            unsafe { ffi::BIO_free_all(rbio) }
            return Err(SslError::get().unwrap());
        }

        unsafe { ffi::SSL_set_bio(ssl.ssl, rbio, wbio) }
        Ok(ssl)
    }

    fn get_rbio<'a>(&'a self) -> MemBio<'a> {
        let bio = unsafe { ffi::SSL_get_rbio(self.ssl) };
        assert!(bio != ptr::null());

        MemBio {
            ssl: self,
            bio: bio
        }
    }

    fn get_wbio<'a>(&'a self) -> MemBio<'a> {
        let bio = unsafe { ffi::SSL_get_wbio(self.ssl) };
        assert!(bio != ptr::null());

        MemBio {
            ssl: self,
            bio: bio
        }
    }

    fn connect(&self) -> c_int {
        unsafe { ffi::SSL_connect(self.ssl) }
    }

    fn read(&self, buf: &mut [u8]) -> c_int {
        unsafe { ffi::SSL_read(self.ssl, vec::raw::to_ptr(buf) as *c_void,
                               buf.len() as c_int) }
    }

    fn write(&self, buf: &[u8]) -> c_int {
        unsafe { ffi::SSL_write(self.ssl, vec::raw::to_ptr(buf) as *c_void,
                                buf.len() as c_int) }
    }

    fn get_error(&self, ret: c_int) -> LibSslError {
        let err = unsafe { ffi::SSL_get_error(self.ssl, ret) };
        match FromPrimitive::from_int(err as int) {
            Some(err) => err,
            None => unreachable!()
        }
    }
}

#[deriving(FromPrimitive)]
enum LibSslError {
    ErrorNone = ffi::SSL_ERROR_NONE,
    ErrorSsl = ffi::SSL_ERROR_SSL,
    ErrorWantRead = ffi::SSL_ERROR_WANT_READ,
    ErrorWantWrite = ffi::SSL_ERROR_WANT_WRITE,
    ErrorWantX509Lookup = ffi::SSL_ERROR_WANT_X509_LOOKUP,
    ErrorSyscall = ffi::SSL_ERROR_SYSCALL,
    ErrorZeroReturn = ffi::SSL_ERROR_ZERO_RETURN,
    ErrorWantConnect = ffi::SSL_ERROR_WANT_CONNECT,
    ErrorWantAccept = ffi::SSL_ERROR_WANT_ACCEPT,
}

struct MemBio<'self> {
    ssl: &'self Ssl,
    bio: *ffi::BIO
}

impl<'self> MemBio<'self> {
    fn read(&self, buf: &mut [u8]) -> Option<uint> {
        let ret = unsafe {
            ffi::BIO_read(self.bio, vec::raw::to_ptr(buf) as *c_void,
                          buf.len() as c_int)
        };

        if ret < 0 {
            None
        } else {
            Some(ret as uint)
        }
    }

    fn write(&self, buf: &[u8]) {
        let ret = unsafe {
            ffi::BIO_write(self.bio, vec::raw::to_ptr(buf) as *c_void,
                           buf.len() as c_int)
        };
        assert_eq!(buf.len(), ret as uint);
    }
}

pub struct SslStream<S> {
    priv stream: S,
    priv ssl: Ssl,
    priv buf: ~[u8]
}

impl<S: Stream> SslStream<S> {
    pub fn try_new(ctx: &SslContext, stream: S) -> Result<SslStream<S>,
                                                          SslError> {
        let ssl = match Ssl::try_new(ctx) {
            Ok(ssl) => ssl,
            Err(err) => return Err(err)
        };

        let mut ssl = SslStream {
            stream: stream,
            ssl: ssl,
            // Maximum TLS record size is 16k
            buf: vec::from_elem(16 * 1024, 0u8)
        };

        match ssl.in_retry_wrapper(|ssl| { ssl.connect() }) {
            Ok(_) => Ok(ssl),
            Err(err) => Err(err)
        }
    }

    pub fn new(ctx: &SslContext, stream: S) -> SslStream<S> {
        match SslStream::try_new(ctx, stream) {
            Ok(stream) => stream,
            Err(err) => fail!("Error creating SSL stream: {:?}", err)
        }
    }

    fn in_retry_wrapper(&mut self, blk: &fn(&Ssl) -> c_int)
            -> Result<c_int, SslError> {
        loop {
            let ret = blk(&self.ssl);
            if ret > 0 {
                return Ok(ret);
            }

            match self.ssl.get_error(ret) {
                ErrorWantRead => {
                    self.flush();
                    match self.stream.read(self.buf) {
                        Some(len) =>
                            self.ssl.get_rbio().write(self.buf.slice_to(len)),
                        None => return Err(StreamEof)
                    }
                }
                ErrorWantWrite => self.flush(),
                ErrorZeroReturn => return Err(SslSessionClosed),
                ErrorSsl => return Err(SslError::get().unwrap()),
                _ => unreachable!()
            }
        }
    }

    fn write_through(&mut self) {
        loop {
            match self.ssl.get_wbio().read(self.buf) {
                Some(len) => self.stream.write(self.buf.slice_to(len)),
                None => break
            }
        }
    }
}

impl<S: Stream> Reader for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        match self.in_retry_wrapper(|ssl| { ssl.read(buf) }) {
            Ok(len) => Some(len as uint),
            Err(StreamEof) | Err(SslSessionClosed) => None,
            _ => unreachable!()
        }
    }

    fn eof(&mut self) -> bool {
        self.stream.eof()
    }
}

impl<S: Stream> Writer for SslStream<S> {
    fn write(&mut self, buf: &[u8]) {
        let mut start = 0;
        while start < buf.len() {
            let ret = do self.in_retry_wrapper |ssl| {
                ssl.write(buf.slice_from(start))
            };
            match ret {
                Ok(len) => start += len as uint,
                _ => unreachable!()
            }
            self.write_through();
        }
    }

    fn flush(&mut self) {
        self.write_through();
        self.stream.flush()
    }
}

impl<S> Decorator<S> for SslStream<S> {
    fn inner(self) -> S {
        self.stream
    }

    fn inner_ref<'a>(&'a self) -> &'a S {
        &self.stream
    }

    fn inner_mut_ref<'a>(&'a mut self) -> &'a mut S {
        &mut self.stream
    }
}
