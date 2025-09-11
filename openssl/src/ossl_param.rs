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
use crate::util;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_void};
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr;

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

impl OsslParamArray {
    /// Locates the individual `OSSL_PARAM` element representing an
    /// octet string identified by the key in the `OsslParamArray`
    /// array and returns a reference to it.
    ///
    /// Combines OSSL_PARAM_locate and OSSL_PARAM_get_octet_string.
    #[corresponds(OSSL_PARAM_get_octet_string)]
    #[allow(dead_code)] // TODO: remove when when used by ML-DSA / ML-KEM
    pub(crate) fn locate_octet_string<'a>(&'a self, key: &CStr) -> Result<&'a [u8], ErrorStack> {
        unsafe {
            let param = cvt_p(ffi::OSSL_PARAM_locate(self.as_ptr(), key.as_ptr()))?;
            let mut val: *const c_void = ptr::null_mut();
            let mut val_len: usize = 0;
            cvt(ffi::OSSL_PARAM_get_octet_string_ptr(
                param,
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

    /// Builder used to construct `OsslParamArray`.
    pub struct OsslParamBuilderInternal;
    /// Reference to `OsslParamBuilderInternal`.
    pub struct OsslParamBuilderRefInternal;
}

/// Wrapper around the internal OsslParamBuilderInternal that adds lifetime management
/// since the builder does not own the key and value data that is added to it.
pub struct OsslParamBuilder<'a> {
    builder: OsslParamBuilderInternal,
    _marker: PhantomData<&'a ()>,
}

impl<'a> OsslParamBuilder<'a> {
    /// Returns a builder for an OsslParamArray.
    ///
    /// The array is initially empty.
    #[corresponds(OSSL_PARAM_BLD_new)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn new() -> Result<OsslParamBuilder<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::OSSL_PARAM_BLD_new()).map(|builder| OsslParamBuilder {
                builder: OsslParamBuilderInternal(builder),
                _marker: PhantomData,
            })
        }
    }

    /// Constructs the `OsslParamArray` and clears this builder.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_param(&'a mut self) -> Result<OsslParamArray, ErrorStack> {
        unsafe {
            let params = cvt_p(ffi::OSSL_PARAM_BLD_to_param(self.as_ptr()))?;
            Ok(OsslParamArray::from_ptr(params))
        }
    }

    /// Adds an octet string to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_octet_string)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn add_octet_string(
        &mut self,
        key: &'a CStr,
        buf: &'a [u8],
    ) -> Result<(), ErrorStack> {
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

    /// Adds an unsigned int to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_uint)]
    #[cfg_attr(any(not(ossl320), osslconf = "OPENSSL_NO_ARGON2"), allow(dead_code))]
    pub(crate) fn add_uint(&mut self, key: &'a CStr, val: u32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_uint(
                self.as_ptr(),
                key.as_ptr(),
                val,
            ))
            .map(|_| ())
        }
    }

    /// Adds a `BigNum` to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    #[allow(dead_code)] // TODO: remove when when used by EVP_KEY.from_data
    pub(crate) fn add_bn(&mut self, key: &'a CStr, bn: &'a BigNumRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::OSSL_PARAM_BLD_push_BN(self.as_ptr(), key.as_ptr(), bn.as_ptr()) })
            .map(|_| ())
    }

    /// Adds a utf8 string to `OsslParamBuilder`.
    #[corresponds(OSSL_PARAM_BLD_push_utf8_string)]
    #[allow(dead_code)] // TODO: remove when when used by EVP_KEY.from_data
    pub(crate) fn add_utf8_string(
        &mut self,
        key: &'a CStr,
        value: &'a str,
    ) -> Result<(), ErrorStack> {
        cvt(unsafe {
            ffi::OSSL_PARAM_BLD_push_utf8_string(
                self.as_ptr(),
                key.as_ptr(),
                value.as_ptr().cast::<c_char>(),
                value.len(),
            )
        })
        .map(|_| ())
    }

    /// Returns a raw pointer to the underlying `OSSL_PARAM_BLD` structure.
    pub(crate) unsafe fn as_ptr(&mut self) -> *mut ffi::OSSL_PARAM_BLD {
        self.builder.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_builder_locate_octet_string() {
        let mut builder = OsslParamBuilder::new().unwrap();
        builder
            .add_octet_string(CStr::from_bytes_with_nul(b"key1\0").unwrap(), b"value1")
            .unwrap();
        let params = builder.to_param().unwrap();

        assert!(params
            .locate_octet_string(CStr::from_bytes_with_nul(b"invalid\0").unwrap())
            .is_err());
        assert_eq!(
            params
                .locate_octet_string(CStr::from_bytes_with_nul(b"key1\0").unwrap())
                .unwrap(),
            b"value1"
        );
    }
}
