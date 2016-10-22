#![allow(bad_style)]

extern crate openssl_sys;
extern crate libc;

use libc::*;
use openssl_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
