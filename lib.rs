#![feature(struct_variant, macro_rules)]
#![crate_id="github.com/sfackler/rust-openssl#openssl:0.0"]
#![crate_type="rlib"]
#![crate_type="dylib"]
#![doc(html_root_url="http://www.rust-ci.org/sfackler/rust-openssl/doc")]

#[cfg(test)]
extern crate serialize;
extern crate sync;

pub mod ssl;
pub mod crypto;
