use crate::bn::BigNumRef;
use crate::error::ErrorStack;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use libc::{c_char, c_void};
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::marker::PhantomData;

pub struct Params<'a>(*mut ffi::OSSL_PARAM, PhantomData<&'a ()>);

impl<'a> ForeignType for Params<'a> {
    type CType = ffi::OSSL_PARAM;
    type Ref = ParamsRef<'a>;

    #[inline]
    unsafe fn from_ptr(ptr: *mut ffi::OSSL_PARAM) -> Params<'a> {
        Self(ptr, PhantomData)
    }

    #[inline]
    fn as_ptr(&self) -> *mut ffi::OSSL_PARAM {
        self.0
    }
}

impl Drop for Params<'_> {
    fn drop(&mut self) {
        unsafe { ffi::OSSL_PARAM_free(self.0) };
    }
}

impl Clone for Params<'_> {
    #[inline]
    fn clone(&self) -> Self {
        Self(unsafe { ffi::OSSL_PARAM_dup(self.0) }, PhantomData)
    }
}

impl<'a> ToOwned for ParamsRef<'a> {
    type Owned = Params<'a>;

    #[inline]
    fn to_owned(&self) -> Params<'a> {
        unsafe {
            let handle: *mut ffi::OSSL_PARAM = ffi::OSSL_PARAM_dup(self.as_ptr());
            ForeignType::from_ptr(handle)
        }
    }
}

impl<'a> std::ops::Deref for Params<'a> {
    type Target = ParamsRef<'a>;

    #[inline]
    fn deref(&self) -> &ParamsRef<'a> {
        unsafe { ParamsRef::from_ptr(self.as_ptr()) }
    }
}

impl<'a> std::ops::DerefMut for Params<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut ParamsRef<'a> {
        unsafe { ParamsRef::from_ptr_mut(self.as_ptr()) }
    }
}

impl<'a> std::borrow::Borrow<ParamsRef<'a>> for Params<'a> {
    #[inline]
    fn borrow(&self) -> &ParamsRef<'a> {
        self
    }
}

impl<'a> AsRef<ParamsRef<'a>> for Params<'a> {
    #[inline]
    fn as_ref(&self) -> &ParamsRef<'a> {
        self
    }
}

pub struct ParamsRef<'a>(Opaque, PhantomData<&'a ()>);

impl ForeignTypeRef for ParamsRef<'_> {
    type CType = ffi::OSSL_PARAM;
}

unsafe impl Send for Params<'_> {}
unsafe impl Send for ParamsRef<'_> {}
unsafe impl Sync for Params<'_> {}
unsafe impl Sync for ParamsRef<'_> {}

impl<'a> ParamsRef<'a> {
    /// Merges two `ParamsRef` objects into a new `Params` object.
    #[corresponds(OSSL_PARAM_merge)]
    #[allow(dead_code)]
    pub fn merge(&self, other: &ParamsRef<'a>) -> Result<Params<'a>, ErrorStack> {
        cvt_p(unsafe { ffi::OSSL_PARAM_merge(self.as_ptr(), other.as_ptr()) })
            .map(|p| unsafe { Params::from_ptr(p) })
    }

    /// Locate a parameter by the given key.
    #[corresponds(OSSL_PARAM_locate_const)]
    #[allow(dead_code)]
    fn locate(&self, key: &CStr) -> Option<*const ffi::OSSL_PARAM> {
        let param = unsafe { ffi::OSSL_PARAM_locate_const(self.as_ptr(), key.as_ptr()) };
        if param.is_null() {
            None
        } else {
            Some(param)
        }
    }
}

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
    #[allow(dead_code)]
    pub fn new() -> Self {
        unsafe { ParamBuilder(ffi::OSSL_PARAM_BLD_new(), PhantomData) }
    }

    /// Push a BigNum parameter into the builder.
    #[corresponds[OSSL_PARAM_BLD_push_BN]]
    #[allow(dead_code)]
    pub fn push_bignum(self, key: &'b CStr, bn: &'a BigNumRef) -> Result<Self, ErrorStack> {
        cvt(unsafe { ffi::OSSL_PARAM_BLD_push_BN(self.0, key.as_ptr(), bn.as_ptr()) })?;
        Ok(self)
    }

    /// Push a UTF-8 String parameter into the builder.
    #[corresponds[OSSL_PARAM_BLD_push_utf8_string]]
    #[allow(dead_code)]
    pub fn push_utf_string(self, key: &'b CStr, string: &'a str) -> Result<Self, ErrorStack> {
        let value = string.as_bytes();
        cvt(unsafe {
            ffi::OSSL_PARAM_BLD_push_utf8_string(
                self.0,
                key.as_ptr(),
                value.as_ptr().cast::<c_char>(),
                value.len(),
            )
        })?;
        Ok(self)
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
    #[allow(dead_code)]
    pub fn build(self) -> Result<Params<'b>, ErrorStack> {
        let ptr = cvt_p(unsafe { ffi::OSSL_PARAM_BLD_to_param(self.0) })?;
        Ok(unsafe { Params::from_ptr(ptr) })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn::BigNum;
    use crate::util::c_str;

    fn assert_param(params: &ParamsRef<'_>, key: &CStr, is_null: bool) {
        match params.locate(key) {
            Some(_) => assert!(!is_null, "Unexpectedly found param: {key:?}"),
            None => assert!(is_null, "Failed to find param: {key:?}"),
        }
    }

    #[test]
    fn test_param_builder_uint() {
        let params = ParamBuilder::new()
            .push_uint(c_str(b"nonce-type\0"), 42)
            .unwrap()
            .build()
            .unwrap();

        assert_param(&params, c_str(b"nonce-type\0"), false);
        assert_param(&params, c_str(b"group\0"), true);
    }

    #[test]
    fn test_param_builder_size_t() {
        let params = ParamBuilder::new()
            .push_size_t(c_str(b"size\0"), 42)
            .unwrap()
            .build()
            .unwrap();

        assert_param(&params, c_str(b"size\0"), false);
        assert_param(&params, c_str(b"out\0"), true);
    }

    #[test]
    fn test_param_builder_bignum() {
        let a = BigNum::from_u32(0x01).unwrap();
        let b = BigNum::from_u32(0x02).unwrap();
        let c = BigNum::from_u32(0x03).unwrap();

        let params = ParamBuilder::new()
            .push_bignum(c_str(b"a\0"), &a)
            .unwrap()
            .push_bignum(c_str(b"b\0"), &b)
            .unwrap()
            .push_bignum(c_str(b"c\0"), &c)
            .unwrap()
            .build()
            .unwrap();

        for param in [b"a\0", b"b\0", b"c\0"] {
            assert_param(&params, c_str(param), false);
        }

        assert_param(&params, c_str(b"group\0"), true);
    }

    #[test]
    fn test_param_builder_string() {
        let params = ParamBuilder::new()
            .push_utf_string(c_str(b"group\0"), "primve256v1")
            .unwrap()
            .build()
            .unwrap();

        assert_param(&params, c_str(b"group\0"), false);
        assert_param(&params, c_str(b"n\0"), true);
    }

    #[test]
    fn test_param_builder_byte_string() {
        let params = ParamBuilder::new()
            .push_byte_string(c_str(b"pass\0"), b"primve256v1")
            .unwrap()
            .build()
            .unwrap();

        assert_param(&params, c_str(b"pass\0"), false);
        assert_param(&params, c_str(b"group\0"), true);
    }

    #[test]
    fn test_merge() {
        let n = BigNum::from_u32(0xbc747fc5).unwrap();
        let e = BigNum::from_u32(0x10001).unwrap();
        let d = BigNum::from_u32(0x7b133399).unwrap();

        let mut merged_params: Params<'_>;
        let params1 = ParamBuilder::new()
            .push_bignum(c_str(b"n\0"), &n)
            .unwrap()
            .build()
            .unwrap();
        {
            let params2 = ParamBuilder::new()
                .push_bignum(c_str(b"e\0"), &e)
                .unwrap()
                .build()
                .unwrap();
            merged_params = params1.merge(&params2).unwrap();
        }

        // Merge 1 & 2, d (added in 3) should not be present
        assert_param(&merged_params, c_str(b"n\0"), false);
        assert_param(&merged_params, c_str(b"e\0"), false);
        assert_param(&merged_params, c_str(b"d\0"), true);

        {
            let params3 = ParamBuilder::new()
                .push_bignum(c_str(b"d\0"), &d)
                .unwrap()
                .build()
                .unwrap();
            merged_params = merged_params.merge(&params3).unwrap();
        }

        // Merge 3 into 1+2, we should now have all params
        assert_param(&merged_params, c_str(b"n\0"), false);
        assert_param(&merged_params, c_str(b"e\0"), false);
        assert_param(&merged_params, c_str(b"e\0"), false);
    }
}
