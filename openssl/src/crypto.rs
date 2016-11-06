use libc::{c_char, c_int, c_void};
use std::fmt;
use std::ffi::CStr;
use std::slice;
use std::ops::Deref;
use std::str;

pub struct CryptoString(&'static str);

impl Drop for CryptoString {
    fn drop(&mut self) {
        unsafe {
            CRYPTO_free(self.0.as_ptr() as *mut c_void,
                        concat!(file!(), "\0").as_ptr() as *const c_char,
                        line!() as c_int);
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
    pub unsafe fn from_raw_parts(buf: *mut u8, len: usize) -> CryptoString {
        let slice = slice::from_raw_parts(buf, len);
        CryptoString(str::from_utf8_unchecked(slice))
    }

    pub unsafe fn from_null_terminated(buf: *mut c_char) -> CryptoString {
        let slice = CStr::from_ptr(buf).to_bytes();
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

#[cfg(not(ossl110))]
#[allow(non_snake_case)]
unsafe fn CRYPTO_free(buf: *mut c_void, _: *const c_char, _: c_int) {
    ::ffi::CRYPTO_free(buf);
}

#[cfg(ossl110)]
use ffi::CRYPTO_free;
