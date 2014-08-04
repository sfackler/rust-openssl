#![feature(struct_variant, macro_rules)]
#![crate_name="openssl"]
#![crate_type="rlib"]
#![crate_type="dylib"]
#![doc(html_root_url="http://www.rust-ci.org/sfackler/rust-openssl/doc")]

extern crate libc;
#[cfg(test)]
extern crate serialize;
extern crate sync;

pub mod ssl;
pub mod crypto;
pub mod bn;
