use std::unstable::atomics::{AtomicBool, INIT_ATOMIC_BOOL, Acquire, Release};
use std::task;

mod ffi;

static mut STARTED_INIT: AtomicBool = INIT_ATOMIC_BOOL;
static mut FINISHED_INIT: AtomicBool = INIT_ATOMIC_BOOL;

#[fixed_stack_segment]
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
    #[fixed_stack_segment]
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
    #[fixed_stack_segment]
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.ctx); }
    }
}

impl SslCtx {
    #[fixed_stack_segment]
    pub fn new(method: SslMethod) -> SslCtx {
        init();
        SslCtx {
            ctx: unsafe { ffi::SSL_CTX_new(method.to_raw()) }
        }
    }
}
