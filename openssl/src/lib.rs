#![feature(unique)]
#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/openssl")]

#[macro_use]
extern crate bitflags;
extern crate libc;
#[macro_use]
extern crate lazy_static;
extern crate openssl_sys as ffi;

#[cfg(test)]
extern crate rustc_serialize as serialize;

mod macros;

pub mod asn1;
pub mod bn;
pub mod bio;
pub mod crypto;
pub mod ssl;
pub mod x509;
