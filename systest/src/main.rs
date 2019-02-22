#![allow(bad_style)]

extern crate libc;
extern crate openssl_sys;

use libc::*;
use openssl_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
