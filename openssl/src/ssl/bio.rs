use libc::{c_char, c_int, c_long, c_void, strlen};
use ffi::{self, BIO, BIO_CTRL_FLUSH, BIO_TYPE_NONE, BIO_new};
use ffi_extras::{BIO_clear_retry_flags, BIO_set_retry_read, BIO_set_retry_write};
use std::any::Any;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::ptr;
use std::slice;
use std::sync::Arc;

use ssl::error::SslError;

pub struct StreamState<S> {
    pub stream: S,
    pub error: Option<io::Error>,
    pub panic: Option<Box<Any + Send>>,
}

/// Safe wrapper for BIO_METHOD
pub struct BioMethod(ffi::BIO_METHOD);

impl BioMethod {
    pub fn new<S: Read + Write>() -> BioMethod {
        BioMethod(ffi::BIO_METHOD {
            type_: BIO_TYPE_NONE,
            name: b"rust\0".as_ptr() as *const _,
            bwrite: Some(bwrite::<S>),
            bread: Some(bread::<S>),
            bputs: Some(bputs::<S>),
            bgets: None,
            ctrl: Some(ctrl::<S>),
            create: Some(create),
            destroy: Some(destroy::<S>),
            callback_ctrl: None,
        })
    }
}

unsafe impl Send for BioMethod {}

pub fn new<S: Read + Write>(stream: S) -> Result<(*mut BIO, Arc<BioMethod>), SslError> {
    let method = Arc::new(BioMethod::new::<S>());

    let state = Box::new(StreamState {
        stream: stream,
        error: None,
        panic: None,
    });

    unsafe {
        let bio = try_ssl_null!(BIO_new(&method.0));
        (*bio).ptr = Box::into_raw(state) as *mut _;
        (*bio).init = 1;

        return Ok((bio, method));
    }
}

pub unsafe fn take_error<S>(bio: *mut BIO) -> Option<io::Error> {
    let state = state::<S>(bio);
    state.error.take()
}

#[cfg_attr(not(feature = "nightly"), allow(dead_code))]
pub unsafe fn take_panic<S>(bio: *mut BIO) -> Option<Box<Any + Send>> {
    let state = state::<S>(bio);
    state.panic.take()
}

pub unsafe fn get_ref<'a, S: 'a>(bio: *mut BIO) -> &'a S {
    let state: &'a StreamState<S> = mem::transmute((*bio).ptr);
    &state.stream
}

pub unsafe fn get_mut<'a, S: 'a>(bio: *mut BIO) -> &'a mut S {
    &mut state(bio).stream
}

unsafe fn state<'a, S: 'a>(bio: *mut BIO) -> &'a mut StreamState<S> {
    mem::transmute((*bio).ptr)
}

#[cfg(feature = "nightly")]
fn catch_unwind<F, T>(f: F) -> Result<T, Box<Any + Send>>
    where F: FnOnce() -> T
{
    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(f))
}

#[cfg(not(feature = "nightly"))]
fn catch_unwind<F, T>(f: F) -> Result<T, Box<Any + Send>>
    where F: FnOnce() -> T
{
    Ok(f())
}

unsafe extern "C" fn bwrite<S: Write>(bio: *mut BIO, buf: *const c_char, len: c_int) -> c_int {
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

unsafe extern "C" fn bread<S: Read>(bio: *mut BIO, buf: *mut c_char, len: c_int) -> c_int {
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

unsafe extern "C" fn bputs<S: Write>(bio: *mut BIO, s: *const c_char) -> c_int {
    bwrite::<S>(bio, s, strlen(s) as c_int)
}

unsafe extern "C" fn ctrl<S: Write>(bio: *mut BIO,
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

unsafe extern "C" fn create(bio: *mut BIO) -> c_int {
    (*bio).init = 0;
    (*bio).num = 0;
    (*bio).ptr = ptr::null_mut();
    (*bio).flags = 0;
    1
}

unsafe extern "C" fn destroy<S>(bio: *mut BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }

    assert!(!(*bio).ptr.is_null());
    Box::<StreamState<S>>::from_raw((*bio).ptr as *mut _);
    (*bio).ptr = ptr::null_mut();
    (*bio).init = 0;
    1
}
