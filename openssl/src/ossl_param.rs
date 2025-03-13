//! OSSL_PARAM management for OpenSSL 3.*
//!
//! The OSSL_PARAM structure represents generic attribute that can represent various
//! properties in OpenSSL, including keys and operations.
//!
//! For convinience, the OSSL_PARAM_BLD builder can be used to dynamically construct
//! these structure.
//!
//! Note, that this module is available only in OpenSSL 3.* and
//! only internally for this crate!
//!
use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::util;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_uint, c_void};
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_PARAM;
    fn drop = ffi::OSSL_PARAM_free;

    /// `OsslParam` constructed using `OsslParamBuilder`.
    pub struct OsslParam;
    /// Reference to `OsslParam`.
    pub struct OsslParamRef;
}

impl OsslParam {}

impl OsslParamRef {
    /// Locates the `OsslParam` in the `OsslParam` array
    #[corresponds(OSSL_PARAM_locate)]
    pub fn locate(&self, key: &[u8]) -> Result<&OsslParamRef, ErrorStack> {
        unsafe {
            let param = cvt_p(ffi::OSSL_PARAM_locate(
                self.as_ptr(),
                key.as_ptr() as *const c_char,
            ))?;
            Ok(OsslParamRef::from_ptr(param))
        }
    }

    /// Get `BigNum` from the current `OsslParam`
    #[allow(dead_code)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn get_bn(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            let mut bn: *mut ffi::BIGNUM = ptr::null_mut();
            cvt(ffi::OSSL_PARAM_get_BN(self.as_ptr(), &mut bn))?;
            Ok(BigNum::from_ptr(bn))
        }
    }

    /// Get `&str` from the current `OsslParam`
    #[allow(dead_code)]
    #[corresponds(OSSL_PARAM_get_utf8_string)]
    pub fn get_utf8_string(&self) -> Result<&str, ErrorStack> {
        unsafe {
            let mut val: *const c_char = ptr::null_mut();
            cvt(ffi::OSSL_PARAM_get_utf8_string_ptr(self.as_ptr(), &mut val))?;
            Ok(CStr::from_ptr(val).to_str().unwrap())
        }
    }

    /// Get octet string (as `&[u8]) from the current `OsslParam`
    #[corresponds(OSSL_PARAM_get_octet_string)]
    pub fn get_octet_string(&self) -> Result<&[u8], ErrorStack> {
        unsafe {
            let mut val: *const c_void = ptr::null_mut();
            let mut val_len: usize = 0;
            cvt(ffi::OSSL_PARAM_get_octet_string_ptr(
                self.as_ptr(),
                &mut val,
                &mut val_len,
            ))?;
            Ok(util::from_raw_parts(val as *const u8, val_len))
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_PARAM_BLD;
    fn drop = ffi::OSSL_PARAM_BLD_free;

    /// Builder used to construct `OsslParam`.
    pub struct OsslParamBuilder;
    /// Reference to `OsslParamBuilder`.
    pub struct OsslParamBuilderRef;
}

impl OsslParamBuilder {
    /// Returns a builder for a OsslParam arrays.
    ///
    /// The array is initially empty.
    #[corresponds(OSSL_PARAM_BLD_new)]
    pub fn new() -> Result<OsslParamBuilder, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::OSSL_PARAM_BLD_new()).map(OsslParamBuilder)
        }
    }

    /// Constructs the `OsslParam`.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    pub fn to_param(&self) -> Result<OsslParam, ErrorStack> {
        unsafe {
            let params = cvt_p(ffi::OSSL_PARAM_BLD_to_param(self.0))?;
            Ok(OsslParam::from_ptr(params))
        }
    }
}

impl OsslParamBuilderRef {
    /// Adds a `BigNum` to `OsslParamBuilder`.
    ///
    /// Note, that both key and bn need to exist until the `to_param` is called!
    #[allow(dead_code)]
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    pub fn add_bn(&self, key: &[u8], bn: &BigNumRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_BN(
                self.as_ptr(),
                key.as_ptr() as *const c_char,
                bn.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Adds a utf8 string to `OsslParamBuilder`.
    ///
    /// Note, that both `key` and `buf` need to exist until the `to_param` is called!
    #[allow(dead_code)]
    #[corresponds(OSSL_PARAM_BLD_push_utf8_string)]
    pub fn add_utf8_string(&self, key: &[u8], buf: &str) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_utf8_string(
                self.as_ptr(),
                key.as_ptr() as *const c_char,
                buf.as_ptr() as *const c_char,
                buf.len(),
            ))
            .map(|_| ())
        }
    }

    /// Adds a octet string to `OsslParamBuilder`.
    ///
    /// Note, that both `key` and `buf` need to exist until the `to_param` is called!
    #[corresponds(OSSL_PARAM_BLD_push_octet_string)]
    pub fn add_octet_string(&self, key: &[u8], buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_octet_string(
                self.as_ptr(),
                key.as_ptr() as *const c_char,
                buf.as_ptr() as *const c_void,
                buf.len(),
            ))
            .map(|_| ())
        }
    }

    /// Adds a unsigned int to `OsslParamBuilder`.
    ///
    /// Note, that both `key` and `buf` need to exist until the `to_param` is called!
    #[corresponds(OSSL_PARAM_BLD_push_uint)]
    pub fn add_uint(&self, key: &[u8], val: u32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_uint(
                self.as_ptr(),
                key.as_ptr() as *const c_char,
                val as c_uint,
            ))
            .map(|_| ())
        }
    }
}
