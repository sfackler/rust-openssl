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

mod macros;

pub mod asn1;
mod bio;
pub mod bn;
pub mod crypto;
pub mod dh;
pub mod error;
pub mod nid;
pub mod ssl;
pub mod version;
pub mod x509;
mod opaque;

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
    if r < 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
