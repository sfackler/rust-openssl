use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long};
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::path::Path;
use std::ptr;
use std::slice;
use std::str;

use asn1::{Asn1BitStringRef, Asn1IntegerRef, Asn1ObjectRef, Asn1StringRef, Asn1TimeRef};
use bio::MemBioSlice;
use conf::ConfRef;
use error::ErrorStack;
use ex_data::Index;
use hash::{DigestBytes, MessageDigest};
use nid::Nid;
use pkey::{HasPrivate, HasPublic, PKey, PKeyRef, Public};
use ssl::SslRef;
use stack::{Stack, StackRef, Stackable};
use string::OpensslString;
use {cvt, cvt_n, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::SRTP_PROTECTION_PROFILE;
    fn drop = SRTP_PROTECTION_PROFILE_free;

    /// Permit additional fields to be added to an `X509` v3 certificate.
    pub struct X509Extension;
    /// Reference to `X509Extension`.
    pub struct X509ExtensionRef;
}

impl Stackable for X509Extension {
    type StackType = ffi::stack_st_SRTP_PROTECTION_PROFILE;
}
