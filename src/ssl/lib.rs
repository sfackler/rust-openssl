use std::rt::io::{Stream, Decorator};
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
        ffi::SSL_load_error_strings();
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
}

struct Ssl {
    ssl: *ffi::SSL
}

impl Drop for Ssl {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.ssl); }
    }
}

enum SslError {
    ErrorNone,
    ErrorSsl,
    ErrorWantRead,
    ErrorWantWrite,
    ErrorWantX509Lookup,
    ErrorZeroReturn,
    ErrorWantConnect,
    ErrorWantAccept,
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
        match unsafe { ffi::SSL_get_error(self.ssl, ret as c_int) } {
            ffi::SSL_ERROR_NONE => ErrorNone,
            ffi::SSL_ERROR_SSL => ErrorSsl,
            ffi::SSL_ERROR_WANT_READ => ErrorWantRead,
            ffi::SSL_ERROR_WANT_WRITE => ErrorWantWrite,
            ffi::SSL_ERROR_WANT_X509_LOOKUP => ErrorWantX509Lookup,
            ffi::SSL_ERROR_ZERO_RETURN => ErrorZeroReturn,
            ffi::SSL_ERROR_WANT_CONNECT => ErrorWantConnect,
            ffi::SSL_ERROR_WANT_ACCEPT => ErrorWantAccept,
            _ => unreachable!()
        }
    }
}

struct MemBio {
    bio: *ffi::BIO
}

impl Drop for MemBio {
    fn drop(&mut self) {
        unsafe { ffi::BIO_free(self.bio); }
    }
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
                fail2!("read returned {}", ret);
            }
            ret as uint
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
    pub fn new(ctx: SslCtx, stream: S) -> SslStream<S> {
        let ssl = Ssl::new(&ctx);

        let rbio = MemBio::new();
        let wbio = MemBio::new();

        ssl.set_bio(&rbio, &wbio);
        ssl.set_connect_state();

        let mut stream = SslStream {
            ctx: ctx,
            ssl: ssl,
            buf: vec::from_elem(16 * 1024, 0u8),
            rbio: rbio,
            wbio: wbio,
            stream: stream
        };

        stream.connect();

        stream
    }

    fn connect(&mut self) {
        info!("in connect");
        loop {
            let ret = self.ssl.connect();
            info2!("connect returned {}", ret);
            if ret == 1 {
                return;
            }

            match self.ssl.get_error(ret) {
                ErrorWantRead => {
                    info2!("want read");
                    self.flush();
                    match self.stream.read(self.buf) {
                        Some(len) => self.rbio.write(self.buf.slice_to(len)),
                        None => unreachable!()
                    }
                }
                ErrorWantWrite => {
                    info2!("want write");
                    self.flush();
                }
                _ => unreachable!()
            }
        }
    }

    fn flush(&mut self) {
        let len = self.wbio.read(self.buf);
        self.stream.write(self.buf.slice_to(len));
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
