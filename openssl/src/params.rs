use crate::bn::BigNumRef;
use crate::error::ErrorStack;
use crate::{cvt, cvt_p};
use foreign_types::ForeignType;
use libc::{c_char, c_void};
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::marker::PhantomData;

pub struct ParamBuilder<'a>(*mut ffi::OSSL_PARAM_BLD, PhantomData<&'a ()>);

impl Drop for ParamBuilder<'_> {
    #[inline]
    fn drop(&mut self) {
        unsafe { ffi::OSSL_PARAM_BLD_free(self.0) }
    }
}

unsafe impl Send for ParamBuilder<'_> {}
unsafe impl Sync for ParamBuilder<'_> {}

impl<'a, 'b> ParamBuilder<'a> {
    /// Creates a new `ParamBuilder`.
    #[corresponds[OSSL_PARAM_BLD_new]]
    pub fn new() -> Self {
        unsafe { ParamBuilder(ffi::OSSL_PARAM_BLD_new(), PhantomData) }
    }

    /// Push a BigNum parameter into the builder.
    #[corresponds[OSSL_PARAM_BLD_push_BN]]
    pub fn push_bignum(&mut self, key: &'b CStr, bn: &'a BigNumRef) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::OSSL_PARAM_BLD_push_BN(self.0, key.as_ptr(), bn.as_ptr()) }).map(|_| ())
    }

    /// Push a UTF-8 String parameter into the builder.
    #[corresponds[OSSL_PARAM_BLD_push_utf8_string]]
    pub fn push_utf_string(&mut self, key: &'b CStr, string: &'a str) -> Result<(), ErrorStack> {
        let value = string.as_bytes();
        cvt(unsafe {
            ffi::OSSL_PARAM_BLD_push_utf8_string(
                self.0,
                key.as_ptr(),
                value.as_ptr().cast::<c_char>(),
                value.len(),
            )
        })
        .map(|_| ())
    }

    /// Push a byte string parameter into the builder.
    #[corresponds[OSSL_PARAM_BLD_push_utf8_string]]
    #[allow(dead_code)]
    pub fn push_byte_string(self, key: &'b CStr, value: &'a [u8]) -> Result<Self, ErrorStack> {
        cvt(unsafe {
            ffi::OSSL_PARAM_BLD_push_octet_string(
                self.0,
                key.as_ptr(),
                value.as_ptr().cast::<c_void>(),
                value.len(),
            )
        })?;
        Ok(self)
    }

    /// Push a uint parameter into the builder.
    #[corresponds[OSSL_PARAM_BLD_push_uint]]
    #[allow(dead_code)]
    pub fn push_uint(self, key: &'b CStr, val: u32) -> Result<Self, ErrorStack> {
        cvt(unsafe { ffi::OSSL_PARAM_BLD_push_uint(self.0, key.as_ptr(), val) })?;
        Ok(self)
    }

    /// Push a size_t parameter into the builder.
    #[corresponds[OSSL_PARAM_BLD_push_size_t]]
    #[allow(dead_code)]
    pub fn push_size_t(self, key: &'b CStr, val: usize) -> Result<Self, ErrorStack> {
        cvt(unsafe { ffi::OSSL_PARAM_BLD_push_size_t(self.0, key.as_ptr(), val) })?;
        Ok(self)
    }

    /// Build a `Params` array from the builder consuming the builder.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    pub fn build(self) -> Result<*mut ffi::OSSL_PARAM, ErrorStack> {
        cvt_p(unsafe { ffi::OSSL_PARAM_BLD_to_param(self.0) })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn::BigNum;
    use crate::util::c_str;

    fn assert_param(params: *mut ffi::OSSL_PARAM, key: &CStr, is_null: bool) {
        let param = unsafe { ffi::OSSL_PARAM_locate_const(params, key.as_ptr()) };
        if is_null {
            assert!(param.is_null(), "Unexpectedly found param: {key:?}");
        } else {
            assert!(!param.is_null(), "Failed to find param: {key:?}");
        }
    }

    #[test]
    fn test_param_builder_uint() {
        let params = ParamBuilder::new()
            .push_uint(c_str(b"nonce-type\0"), 42)
            .unwrap()
            .build()
            .unwrap();

        assert_param(params, c_str(b"nonce-type\0"), false);
        assert_param(params, c_str(b"group\0"), true);
    }

    #[test]
    fn test_param_builder_size_t() {
        let params = ParamBuilder::new()
            .push_size_t(c_str(b"size\0"), 42)
            .unwrap()
            .build()
            .unwrap();

        assert_param(params, c_str(b"size\0"), false);
        assert_param(params, c_str(b"out\0"), true);
    }

    #[test]
    fn test_param_builder_bignum() {
        let n = BigNum::from_u32(0xbc747fc5).unwrap();
        let e = BigNum::from_u32(0x10001).unwrap();
        let d = BigNum::from_u32(0x7b133399).unwrap();

        let mut builder = ParamBuilder::new();
        builder.push_bignum(c_str(b"n\0"), &n).unwrap();
        builder.push_bignum(c_str(b"e\0"), &e).unwrap();
        builder.push_bignum(c_str(b"d\0"), &d).unwrap();
        let params = builder.build().unwrap();

        for param in [b"n\0", b"e\0", b"d\0"] {
            assert_param(params, c_str(param), false);
        }

        assert_param(params, c_str(b"group\0"), true);
    }

    #[test]
    fn test_param_builder_string() {
        let mut builder = ParamBuilder::new();
        builder
            .push_utf_string(c_str(b"group\0"), "primve256v1")
            .unwrap();
        let params = builder.build().unwrap();

        assert_param(params, c_str(b"group\0"), false);
        assert_param(params, c_str(b"n\0"), true);
    }

    #[test]
    fn test_param_builder_byte_string() {
        let params = ParamBuilder::new()
            .push_byte_string(c_str(b"pass\0"), b"primve256v1")
            .unwrap()
            .build()
            .unwrap();

        assert_param(params, c_str(b"pass\0"), false);
        assert_param(params, c_str(b"group\0"), true);
    }
}
