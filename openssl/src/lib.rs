#![doc(html_root_url="https://docs.rs/openssl/0.9.6")]

#[macro_use]
extern crate bitflags;
extern crate libc;
#[macro_use]
extern crate lazy_static;
extern crate openssl_sys as ffi;

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate tempdir;

#[doc(inline)]
pub use ffi::init;

use libc::c_int;

use error::ErrorStack;

#[macro_use]
mod macros;

mod bio;
mod util;
pub mod asn1;
pub mod bn;
pub mod crypto;
pub mod dh;
pub mod dsa;
pub mod ec;
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

fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_n(r: c_int) -> Result<c_int, ErrorStack> {
    if r < 0 { Err(ErrorStack::get()) } else { Ok(r) }
}
