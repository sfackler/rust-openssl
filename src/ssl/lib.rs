use std::rt::io::{Stream, Decorator};
use std::unstable::atomics::{AtomicBool, INIT_ATOMIC_BOOL, Acquire, Release};
use std::task;
use std::ptr;

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
}

pub struct SslStream<S> {
    priv ctx: SslCtx,
    priv ssl: Ssl,
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

        let stream = SslStream {
            ctx: ctx,
            ssl: ssl,
            rbio: rbio,
            wbio: wbio,
            stream: stream
        }

        stream
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
