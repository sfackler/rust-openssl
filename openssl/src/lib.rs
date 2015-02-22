#![feature(unsafe_destructor, core, old_io, std_misc, old_path)]
#![doc(html_root_url="https://sfackler.github.io/rust-openssl/doc/openssl")]

extern crate libc;
#[cfg(test)]
extern crate "rustc-serialize" as serialize;

extern crate "openssl-sys" as ffi;

mod macros;

pub mod asn1;
pub mod bn;
pub mod bio;
pub mod crypto;
pub mod ssl;
pub mod x509;
