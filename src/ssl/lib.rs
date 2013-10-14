#[link(name="ssl")];

use std::rt::io::{Reader, Writer, Stream, Decorator};
use std::unstable::atomics::{AtomicBool, INIT_ATOMIC_BOOL, Acquire, Release};
use std::task;
use std::ptr;
use std::vec;
use std::libc::{c_int, c_void};

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
    Sslv23
}

impl SslMethod {
    unsafe fn to_raw(&self) -> *ffi::SSL_METHOD {
        match *self {
            Sslv23 => ffi::SSLv23_method()
        }
    }
}

pub struct SslCtx {
    priv ctx: *ffi::SSL_CTX
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx); }
    }
}

impl SslCtx {
    pub fn new(method: SslMethod) -> SslCtx {
        init();

        let ctx = unsafe { ffi::SSL_CTX_new(method.to_raw()) };
        assert!(ctx != ptr::null());

        SslCtx {
            ctx: ctx
        }
    }

    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe { ffi::SSL_CTX_set_verify(self.ctx, mode as c_int, None) }
    }
}

pub enum SslVerifyMode {
    SslVerifyNone = ffi::SSL_VERIFY_NONE,
    SslVerifyPeer = ffi::SSL_VERIFY_PEER
}

#[deriving(Eq, FromPrimitive)]
enum SslError {
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

struct Ssl {
    ssl: *ffi::SSL
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl); }
    }
}

impl Ssl {
    fn new(ctx: &SslCtx) -> Ssl {
        let ssl = unsafe { ffi::SSL_new(ctx.ctx) };
        assert!(ssl != ptr::null());

        Ssl { ssl: ssl }
    }

    fn set_bio(&self, rbio: &MemBio, wbio: &MemBio) {
        unsafe { ffi::SSL_set_bio(self.ssl, rbio.bio, wbio.bio); }
    }

    fn set_connect_state(&self) {
        unsafe { ffi::SSL_set_connect_state(self.ssl); }
    }

    fn connect(&self) -> int {
        unsafe { ffi::SSL_connect(self.ssl) as int }
    }

    fn get_error(&self, ret: int) -> SslError {
        let err = unsafe { ffi::SSL_get_error(self.ssl, ret as c_int) };
        match FromPrimitive::from_int(err as int) {
            Some(err) => err,
            None => fail2!("Unknown error {}", err)
        }
    }

    fn read(&self, buf: &[u8]) -> int {
        unsafe {
            ffi::SSL_read(self.ssl, vec::raw::to_ptr(buf) as *c_void,
                          buf.len() as c_int) as int
        }
    }

    fn write(&self, buf: &[u8]) -> int {
        unsafe {
            ffi::SSL_write(self.ssl, vec::raw::to_ptr(buf) as *c_void,
                           buf.len() as c_int) as int
        }
    }

    fn shutdown(&self) -> int {
        unsafe { ffi::SSL_shutdown(self.ssl) as int }
    }
}

// BIOs are freed by SSL_free
struct MemBio {
    bio: *ffi::BIO
}

impl MemBio {
    fn new() -> MemBio {
        let bio = unsafe { ffi::BIO_new(ffi::BIO_s_mem()) };
        assert!(bio != ptr::null());

        MemBio { bio: bio }
    }

    fn write(&self, buf: &[u8]) {
        unsafe {
            let ret = ffi::BIO_write(self.bio,
                                     vec::raw::to_ptr(buf) as *c_void,
                                     buf.len() as c_int);
            if ret < 0 {
                fail2!("write returned {}", ret);
            }
        }
    }

    fn read(&self, buf: &[u8]) -> uint {
        unsafe {
            let ret = ffi::BIO_read(self.bio, vec::raw::to_ptr(buf) as *c_void,
                                    buf.len() as c_int);
            if ret < 0 {
                0
            } else {
                ret as uint
            }
        }
    }
}

pub struct SslStream<S> {
    priv ctx: SslCtx,
    priv ssl: Ssl,
    priv buf: ~[u8],
    priv rbio: MemBio,
    priv wbio: MemBio,
    priv stream: S
}

impl<S: Stream> SslStream<S> {
    pub fn new(ctx: SslCtx, stream: S) -> Result<SslStream<S>, uint> {
        let ssl = Ssl::new(&ctx);

        let rbio = MemBio::new();
        let wbio = MemBio::new();

        ssl.set_bio(&rbio, &wbio);
        ssl.set_connect_state();

        let mut stream = SslStream {
            ctx: ctx,
            ssl: ssl,
            // Max record size for SSLv3/TLSv1 is 16k
            buf: vec::from_elem(16 * 1024, 0u8),
            rbio: rbio,
            wbio: wbio,
            stream: stream
        };

        let ret = do stream.in_retry_wrapper |ssl| {
            ssl.ssl.connect()
        };

        match ret {
            Ok(_) => Ok(stream),
            // FIXME
            Err(_err) => Err(unsafe { ffi::ERR_get_error() as uint })
        }
    }

    fn in_retry_wrapper(&mut self, blk: &fn(&mut SslStream<S>) -> int)
                        -> Result<int, SslError> {
        loop {
            let ret = blk(self);
            if ret > 0 {
                return Ok(ret);
            }

            match self.ssl.get_error(ret) {
                ErrorWantRead => {
                    self.flush();
                    match self.stream.read(self.buf) {
                        Some(len) => self.rbio.write(self.buf.slice_to(len)),
                        None => return Err(ErrorZeroReturn) // FIXME
                    }
                }
                ErrorWantWrite => self.flush(),
                err => return Err(err)
            }
        }
    }

    fn write_through(&mut self) {
        loop {
            let len = self.wbio.read(self.buf);
            if len == 0 {
                return;
            }
            self.stream.write(self.buf.slice_to(len));
        }
    }

    pub fn shutdown(&mut self) {
        loop {
            let ret = do self.in_retry_wrapper |ssl| {
                ssl.ssl.shutdown()
            };

            if ret != Ok(0) {
                break;
            }
        }
    }
}

impl<S: Stream> Reader for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        let ret = do self.in_retry_wrapper |ssl| {
            ssl.ssl.read(buf)
        };

        match ret {
            Ok(num) => Some(num as uint),
            Err(_) => None
        }
    }

    fn eof(&mut self) -> bool {
        self.stream.eof()
    }
}

impl<S: Stream> Writer for SslStream<S> {
    fn write(&mut self, buf: &[u8]) {
        let ret = do self.in_retry_wrapper |ssl| {
            ssl.ssl.write(buf)
        };

        match ret {
            Ok(_) => (),
            Err(err) => fail2!("Write error: {:?}", err)
        }

        self.write_through();
    }

    fn flush(&mut self) {
        self.write_through();
        self.stream.flush();
    }
}

impl<S: Stream> Decorator<S> for SslStream<S> {
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
