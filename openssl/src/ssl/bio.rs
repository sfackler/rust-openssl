use libc::{c_char, c_int, c_long, c_void, strlen};
use ffi::{BIO, BIO_CTRL_FLUSH, BIO_new, BIO_clear_retry_flags,
          BIO_set_retry_read, BIO_set_retry_write};
use std::any::Any;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::ptr;
use std::slice;
use std::sync::Arc;

use error::ErrorStack;

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    pub panic: Option<Box<Any + Send>>,
}

/// Safe wrapper for BIO_METHOD
pub struct BioMethod(compat::BIO_METHOD);

impl BioMethod {
    pub fn new<S: Read + Write>() -> BioMethod {
        BioMethod(compat::BIO_METHOD::new::<S>())
    }
}

unsafe impl Send for BioMethod {}

pub fn new<S: Read + Write>(stream: S) -> Result<(*mut BIO, Arc<BioMethod>), ErrorStack> {
    let method = Arc::new(BioMethod::new::<S>());

    let state = Box::new(StreamState {
        stream: stream,
        error: None,
        panic: None,
    });

    unsafe {
        let bio = try_ssl_null!(BIO_new(method.0.get()));
        compat::BIO_set_data(bio, Box::into_raw(state) as *mut _);
        compat::BIO_set_init(bio, 1);

        return Ok((bio, method));
    }
}

pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    let state = state::<S>(bio);
    state.error.take()
}

pub unsafe fn take_panic<S>(bio: *mut BIO) -> Option<Box<Any + Send>> {
    let state = state::<S>(bio);
    state.panic.take()
}

pub unsafe fn get_ref<'a, S: 'a>(bio: *mut BIO) -> &'a S {
    let state: &'a StreamState<S> = mem::transmute(compat::BIO_get_data(bio));
    &state.stream
}

pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    &mut state(bio).stream
}

unsafe fn state<'a, S: 'a>(bio: *mut BIO) -> &'a mut StreamState<S> {
    mem::transmute(compat::BIO_get_data(bio))
}

fn catch_unwind<F, T>(f: F) -> Result<T, Box<Any + Send>>
    where F: FnOnce() -> T
{
    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(f))
}

unsafe extern fn bwrite<S: Write>(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
    BIO_clear_retry_flags(bio);

    let state = state::<S>(bio);
    let buf = slice::from_raw_parts(buf as *const _, len as usize);

    match catch_unwind(|| state.stream.write(buf)) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_write(bio);
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}

unsafe extern fn bread<S: Read>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
    BIO_clear_retry_flags(bio);

    let state = state::<S>(bio);
    let buf = slice::from_raw_parts_mut(buf as *mut _, len as usize);

    match catch_unwind(|| state.stream.read(buf)) {
        Ok(Ok(len)) => len as c_int,
        Ok(Err(err)) => {
            if retriable_error(&err) {
                BIO_set_retry_read(bio);
            }
            state.error = Some(err);
            -1
        }
        Err(err) => {
            state.panic = Some(err);
            -1
        }
    }
}

fn retriable_error(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::WouldBlock |
        io::ErrorKind::NotConnected => true,
        _ => false,
    }
}

unsafe extern fn bputs<S: Write>(bio: *mut BIO, s: *const c_char) -> c_int {
    bwrite::<S>(bio, s, strlen(s) as c_int)
}

unsafe extern fn ctrl<S: Write>(bio: *mut BIO,
                                cmd: c_int,
                                _num: c_long,
                                _ptr: *mut c_void)
                                -> c_long {
    if cmd == BIO_CTRL_FLUSH {
        let state = state::<S>(bio);

        match catch_unwind(|| state.stream.flush()) {
            Ok(Ok(())) => 1,
            Ok(Err(err)) => {
                state.error = Some(err);
                0
            }
            Err(err) => {
                state.panic = Some(err);
                0
            }
        }
    } else {
        0
    }
}

unsafe extern fn create(bio: *mut BIO) -> c_int {
    compat::BIO_set_init(bio, 0);
    compat::BIO_set_num(bio, 0);
    compat::BIO_set_data(bio, ptr::null_mut());
    compat::BIO_set_flags(bio, 0);
    1
}

unsafe extern fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    let data = compat::BIO_get_data(bio);
    assert!(!data.is_null());
    Box::<StreamState<S>>::from_raw(data as *mut _);
    compat::BIO_set_data(bio, ptr::null_mut());
    compat::BIO_set_init(bio, 0);
    1
}

#[cfg(ossl110)]
#[allow(bad_style)]
mod compat {
    use std::io::{Read, Write};

    use libc::c_int;
    use ffi;
    pub use ffi::{BIO_set_init, BIO_set_flags, BIO_set_data, BIO_get_data};

    pub unsafe fn BIO_set_num(_bio: *mut ffi::BIO, _num: c_int) {}

    pub struct BIO_METHOD {
        inner: *mut ffi::BIO_METHOD,
    }

    impl BIO_METHOD {
        pub fn new<S: Read + Write>() -> BIO_METHOD {
            unsafe {
                let ptr = ffi::BIO_meth_new(ffi::BIO_TYPE_NONE,
                                            b"rust\0".as_ptr() as *const _);
                assert!(!ptr.is_null());
                let ret = BIO_METHOD { inner: ptr };
                assert!(ffi::BIO_meth_set_write(ptr, super::bwrite::<S>) != 0);
                assert!(ffi::BIO_meth_set_read(ptr, super::bread::<S>) != 0);
                assert!(ffi::BIO_meth_set_puts(ptr, super::bputs::<S>) != 0);
                assert!(ffi::BIO_meth_set_ctrl(ptr, super::ctrl::<S>) != 0);
                assert!(ffi::BIO_meth_set_create(ptr, super::create) != 0);
                assert!(ffi::BIO_meth_set_destroy(ptr, super::destroy::<S>) != 0);
                return ret
            }
        }

        pub fn get(&self) -> *mut ffi::BIO_METHOD {
            self.inner
        }
    }

    impl Drop for BIO_METHOD {
        fn drop(&mut self) {
            unsafe {
                ffi::BIO_meth_free(self.inner);
            }
        }
    }
}

#[cfg(ossl10x)]
#[allow(bad_style)]
mod compat {
    use std::io::{Read, Write};
    use std::cell::UnsafeCell;

    use ffi;
    use libc::{c_int, c_void};

    pub struct BIO_METHOD {
        inner: UnsafeCell<ffi::BIO_METHOD>,
    }

    impl BIO_METHOD {
        pub fn new<S: Read + Write>() -> BIO_METHOD {
            BIO_METHOD {
                inner: UnsafeCell::new(ffi::BIO_METHOD {
                    type_: ffi::BIO_TYPE_NONE,
                    name: b"rust\0".as_ptr() as *const _,
                    bwrite: Some(super::bwrite::<S>),
                    bread: Some(super::bread::<S>),
                    bputs: Some(super::bputs::<S>),
                    bgets: None,
                    ctrl: Some(super::ctrl::<S>),
                    create: Some(super::create),
                    destroy: Some(super::destroy::<S>),
                    callback_ctrl: None,
                }),
            }
        }

        pub fn get(&self) -> *mut ffi::BIO_METHOD {
            self.inner.get()
        }
    }

    pub unsafe fn BIO_set_init(bio: *mut ffi::BIO, init: c_int) {
        (*bio).init = init;
    }

    pub unsafe fn BIO_set_flags(bio: *mut ffi::BIO, flags: c_int) {
        (*bio).flags = flags;
    }

    pub unsafe fn BIO_get_data(bio: *mut ffi::BIO) -> *mut c_void {
        (*bio).ptr
    }

    pub unsafe fn BIO_set_data(bio: *mut ffi::BIO, data: *mut c_void) {
        (*bio).ptr = data;
    }

    pub unsafe fn BIO_set_num(bio: *mut ffi::BIO, num: c_int) {
        (*bio).num = num;
    }
}
