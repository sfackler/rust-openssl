#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/v0.8.2")]

#[macro_use]
extern crate bitflags;
extern crate libc;
#[macro_use]
extern crate lazy_static;
extern crate openssl_sys as ffi;

#[cfg(test)]
extern crate rustc_serialize as serialize;

#[cfg(test)]
extern crate net2;

#[doc(inline)]
pub use ffi::init;

use nid::Nid;

mod macros;

pub mod asn1;
mod bio;
pub mod bn;
#[cfg(feature = "c_helpers")]
mod c_helpers;
pub mod crypto;
pub mod dh;
pub mod error;
pub mod nid;
pub mod ssl;
pub mod version;
pub mod x509;

trait HashTypeInternals {
    fn as_nid(&self) -> Nid;
    fn evp_md(&self) -> *const ffi::EVP_MD;
}
