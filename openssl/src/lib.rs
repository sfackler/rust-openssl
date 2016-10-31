#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/v0.8.3")]

#[macro_use]
extern crate bitflags;
extern crate libc;
#[macro_use]
extern crate lazy_static;
extern crate openssl_sys as ffi;

#[cfg(test)]
extern crate rustc_serialize as serialize;

#[cfg(test)]
extern crate tempdir;

#[doc(inline)]
pub use ffi::init;

use libc::c_int;

use error::ErrorStack;

macro_rules! type_ {
    ($n:ident, $c:path, $d:path) => {
        pub struct $n(*mut $c);

        unsafe impl ::types::OpenSslType for $n {
            type CType = $c;

            unsafe fn from_ptr(ptr: *mut $c) -> $n {
                $n(ptr)
            }

            fn as_ptr(&self) -> *mut $c {
                self.0
            }
        }

        impl Drop for $n {
            fn drop(&mut self) {
                unsafe { $d(self.0) }
            }
        }

        impl ::std::ops::Deref for $n {
            type Target = ::types::Ref<$n>;

            fn deref(&self) -> &::types::Ref<$n> {
                unsafe { ::types::Ref::from_ptr(self.0) }
            }
        }

        impl ::std::ops::DerefMut for $n {
            fn deref_mut(&mut self) -> &mut ::types::Ref<$n> {
                unsafe { ::types::Ref::from_ptr_mut(self.0) }
            }
        }
    }
}

mod bio;
mod util;
pub mod asn1;
pub mod bn;
pub mod crypto;
pub mod dh;
pub mod dsa;
pub mod ec_key;
pub mod error;
pub mod hash;
pub mod memcmp;
pub mod nid;
pub mod pkcs12;
pub mod pkcs5;
pub mod pkey;
pub mod rand;
pub mod types;
pub mod rsa;
pub mod sign;
pub mod ssl;
pub mod symm;
pub mod version;
pub mod x509;
pub mod stack;
#[cfg(any(ossl102, ossl110))]
mod verify;

pub fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub fn cvt_n(r: c_int) -> Result<c_int, ErrorStack> {
    if r < 0 { Err(ErrorStack::get()) } else { Ok(r) }
}
