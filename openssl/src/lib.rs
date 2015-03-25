#![feature(unsafe_destructor, core, io, std_misc, unique)]
#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/openssl")]

#[macro_use]
extern crate bitflags;

extern crate libc;
#[cfg(test)]
extern crate rustc_serialize as serialize;

extern crate openssl_sys as ffi;

mod macros;

pub mod asn1;
pub mod bn;
pub mod bio;
pub mod crypto;
pub mod ssl;
pub mod x509;
