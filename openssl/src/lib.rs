#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/v0.7.10")]
#![cfg_attr(feature = "nightly", feature(const_fn))]

#[macro_use]
extern crate bitflags;
extern crate libc;
#[macro_use]
extern crate lazy_static;
extern crate openssl_sys as ffi;
extern crate openssl_sys_extras as ffi_extras;

#[cfg(test)]
extern crate rustc_serialize as serialize;

#[cfg(test)]
extern crate net2;

mod macros;

pub mod asn1;
pub mod bio;
pub mod bn;
pub mod crypto;
pub mod dh;
pub mod error;
pub mod nid;
pub mod ssl;
pub mod version;
pub mod x509;
