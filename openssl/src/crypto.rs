use ffi;
use libc::{c_int, c_void};
use std::fmt;
use std::slice;
use std::ops::Deref;
use std::str;

pub struct CryptoString(&'static str);

impl<'s> Drop for CryptoString {
    fn drop(&mut self) {
        unsafe {
            CRYPTO_free!(self.0.as_ptr() as *mut c_void);
        }
    }
}

impl Deref for CryptoString {
    type Target = str;

    fn deref(&self) -> &str {
        self.0
    }
}

impl CryptoString {
    pub unsafe fn from_raw_parts(buf: *const u8, len: usize) -> CryptoString {
        let slice = slice::from_raw_parts(buf, len);
        CryptoString(str::from_utf8_unchecked(slice))
    }
}

impl fmt::Display for CryptoString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.0, f)
    }
}

impl fmt::Debug for CryptoString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}
