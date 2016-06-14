use libc::{c_int, c_char, c_void};

use std::any::Any;
use std::panic;
use std::slice;

/// Wraps a user-supplied callback and a slot for panics thrown inside the callback (while FFI
/// frames are on the stack).
///
/// When dropped, checks if the callback has panicked, and resumes unwinding if so.
pub struct CallbackState<F> {
    /// The user callback. Taken out of the `Option` when called.
    cb: Option<F>,
    /// If the callback panics, we place the panic object here, to be re-thrown once OpenSSL
    /// returns.
    panic: Option<Box<Any + Send + 'static>>,
}

impl<F> CallbackState<F> {
    pub fn new(callback: F) -> Self {
        CallbackState {
            cb: Some(callback),
            panic: None,
        }
    }
}

impl<F> Drop for CallbackState<F> {
    fn drop(&mut self) {
        if let Some(panic) = self.panic.take() {
            panic::resume_unwind(panic);
        }
    }
}

/// Password callback function, passed to private key loading functions.
///
/// `cb_state` is expected to be a pointer to a `CallbackState`.
pub extern "C" fn invoke_passwd_cb<F>(buf: *mut c_char,
                                      size: c_int,
                                      _rwflag: c_int,
                                      cb_state: *mut c_void)
                                      -> c_int
                                      where F: FnMut(&mut [i8]) -> usize {
    let result = panic::catch_unwind(|| {
        // build a `i8` slice to pass to the user callback
        let pass_slice = unsafe { slice::from_raw_parts_mut(buf, size as usize) };
        let callback = unsafe { &mut *(cb_state as *mut CallbackState<F>) };

        callback.cb.take().unwrap()(pass_slice)
    });

    if let Ok(len) = result {
        return len as c_int;
    } else {
        return 0;
    }
}
