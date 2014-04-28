#![feature(struct_variant, macro_rules)]
#![crate_id="github.com/sfackler/rust-openssl#openssl:0.0"]
#![crate_type="rlib"]
#![crate_type="dylib"]
#![doc(html_root_url="http://sfackler.github.io/rust-openssl/doc")]

extern crate libc;
#[cfg(test)]
extern crate serialize;
extern crate sync;

pub mod ssl;
pub mod crypto;
