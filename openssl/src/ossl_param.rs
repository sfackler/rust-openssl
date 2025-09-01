//! OSSL_PARAM management for OpenSSL 3.*
//!
//! The OSSL_PARAM structure represents an array of generic
//! attributes that can represent various
//! properties in OpenSSL, including keys and operations.
//!
//! This is always represented as an array of OSSL_PARAM
//! structures, terminated by an entry with a NULL key.
//!
//! For convinience, the OSSL_PARAM_BLD builder can be used to
//! dynamically construct these structures.
//!
//! Note, that this module is available only in OpenSSL 3.* and
//! only internally for this crate.

use crate::bn::BigNumRef;
use crate::error::ErrorStack;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_uint, c_void};
use openssl_macros::corresponds;
use std::ffi::CStr;

foreign_type_and_impl_send_sync! {
    // This is the singular type, but it is always allocated
    // and used as an array of such types.
    type CType = ffi::OSSL_PARAM;
    // OSSL_PARMA_free correctly frees the entire array.
    fn drop = ffi::OSSL_PARAM_free;

    /// `OsslParamArray` constructed using `OsslParamBuilder`.
    /// Internally this is a pointer to an array of the OSSL_PARAM
    /// structures.
    pub struct OsslParamArray;
    /// Reference to `OsslParamArray`.
    pub struct OsslParamArrayRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_PARAM_BLD;
    fn drop = ffi::OSSL_PARAM_BLD_free;

    /// Builder used to construct `OsslParamArray`.
    pub struct OsslParamBuilder;
    /// Reference to `OsslParamBuilder`.
    pub struct OsslParamBuilderRef;
}

impl OsslParamBuilder {
    /// Returns a builder for an OsslParamArray.
    ///
    /// The array is initially empty.
    #[corresponds(OSSL_PARAM_BLD_new)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn new() -> Result<OsslParamBuilder, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::OSSL_PARAM_BLD_new()).map(OsslParamBuilder)
        }
    }

    /// Constructs the `OsslParamArray` and clears this builder.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_param(&mut self) -> Result<OsslParamArray, ErrorStack> {
        unsafe {
            let params = cvt_p(ffi::OSSL_PARAM_BLD_to_param(self.0))?;
            Ok(OsslParamArray::from_ptr(params))
        }
    }
}

impl OsslParamBuilderRef {
    /// Adds a `BigNum` to `OsslParamBuilder`.
    ///
    /// Note, that both key and bn need to exist until the `to_param` is called!
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    #[allow(dead_code)] // TODO: remove when when used by ML-DSA / ML-KEM
    pub(crate) fn add_bn(&mut self, key: &CStr, bn: &BigNumRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_BN(
                self.as_ptr(),
                key.as_ptr(),
                bn.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Adds a utf8 string to `OsslParamBuilder`.
    ///
    /// Note, that both `key` and `buf` need to exist until the `to_param` is called!
    #[corresponds(OSSL_PARAM_BLD_push_utf8_string)]
    #[allow(dead_code)] // TODO: remove when when used by ML-DSA / ML-KEM
    pub(crate) fn add_utf8_string(&mut self, key: &CStr, buf: &str) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_utf8_string(
                self.as_ptr(),
                key.as_ptr(),
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
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn add_octet_string(&mut self, key: &CStr, buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_octet_string(
                self.as_ptr(),
                key.as_ptr(),
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
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn add_uint(&mut self, key: &CStr, val: u32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_uint(
                self.as_ptr(),
                key.as_ptr(),
                val as c_uint,
            ))
            .map(|_| ())
        }
    }
}
