#![feature(struct_variant, macro_rules, unsafe_destructor)]
#![crate_name="openssl"]
#![crate_type="rlib"]
#![crate_type="dylib"]
#![doc(html_root_url="http://www.rust-ci.org/sfackler/rust-openssl/doc")]

extern crate libc;
#[cfg(test)]
extern crate serialize;
extern crate sync;

mod macros;

pub mod asn1;
pub mod bn;
pub mod bio;
pub mod crypto;
pub mod ffi;
pub mod ssl;
pub mod x509;
