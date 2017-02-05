use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_void};
use std::fmt;
use std::ffi::CStr;
use std::ops::Deref;
use std::str;

use stack::Stackable;

foreign_type! {
    type CType = c_char;
    fn drop = free;

    pub struct OpensslString;
    pub struct OpensslStringRef;
}

impl OpensslString {
    #[deprecated(note = "use from_ptr", since = "0.9.7")]
    pub unsafe fn from_raw_parts(buf: *mut u8, _: usize) -> OpensslString {
        OpensslString::from_ptr(buf as *mut c_char)
    }

    #[deprecated(note = "use from_ptr", since = "0.9.7")]
    pub unsafe fn from_null_terminated(buf: *mut c_char) -> OpensslString {
        OpensslString::from_ptr(buf)
    }
}

impl fmt::Display for OpensslString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl fmt::Debug for OpensslString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl Stackable for OpensslString {
    type StackType = ffi::stack_st_OPENSSL_STRING;
}

impl Deref for OpensslStringRef {
    type Target = str;

    fn deref(&self) -> &str {
        unsafe {
            let slice = CStr::from_ptr(self.as_ptr()).to_bytes();
            str::from_utf8_unchecked(slice)
        }
    }
}

impl fmt::Display for OpensslStringRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl fmt::Debug for OpensslStringRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(not(ossl110))]
unsafe fn free(buf: *mut c_char) {
    ::ffi::CRYPTO_free(buf as *mut c_void);
}

#[cfg(ossl110)]
unsafe fn free(buf: *mut c_char) {
    ::ffi::CRYPTO_free(buf as *mut c_void,
                       concat!(file!(), "\0").as_ptr() as *const c_char,
                       line!() as ::libc::c_int);
}
