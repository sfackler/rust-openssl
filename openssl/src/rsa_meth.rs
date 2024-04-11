use crate::error::ErrorStack;
use crate::{cvt, cvt_p, cvt_p_const};
use ffi::{BIGNUM, BN_CTX, BN_GENCB, BN_MONT_CTX, RSA};
use openssl_macros::corresponds;
use std::ffi::{c_int, c_uchar, c_uint, c_void, CStr, CString};

struct RsaMethod(*mut ffi::RSA_METHOD);

impl RsaMethod {
    /// Creates a new `RSA_METHOD` structure.
    #[corresponds(RSA_meth_new)]
    #[inline]
    pub fn new(name: &str, flags: i32) -> Result<Self, ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            let ptr = cvt_p(ffi::RSA_meth_new(name.as_ptr(), flags))?;
            Ok(RsaMethod::from_ptr(ptr))
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::RSA_METHOD {
        self.0
    }

    pub fn from_ptr(ptr: *mut ffi::RSA_METHOD) -> RsaMethod {
        RsaMethod(ptr)
    }

    #[corresponds(RSA_meth_dup)]
    #[inline]
    fn duplicate(&self) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::RSA_meth_dup(self.as_ptr()))?;
            Ok(RsaMethod::from_ptr(ptr))
        }
    }

    #[corresponds(RSA_meth_get0_name)]
    #[inline]
    pub fn get_name(&self) -> Result<String, ErrorStack> {
        unsafe {
            let name: *const i8 = cvt_p_const(ffi::RSA_meth_get0_name(self.as_ptr()))?;
            Ok(CStr::from_ptr(name).to_str().unwrap().to_owned())
        }
    }

    #[corresponds(RSA_meth_set1_name)]
    #[inline]
    pub fn set_name(&self, name: &str) -> Result<(), ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            cvt(ffi::RSA_meth_set1_name(self.as_ptr(), name.as_ptr()))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_get_flags)]
    #[inline]
    pub fn get_flags(&self) -> Result<i32, ErrorStack> {
        let flags = unsafe { cvt(ffi::RSA_meth_get_flags(self.as_ptr()))? };
        Ok(flags)
    }

    #[corresponds(RSA_meth_set_flags)]
    #[inline]
    pub fn set_flags(&self, flags: i32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_flags(self.as_ptr(), flags))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_get0_app_data)]
    #[inline]
    pub fn get_app_data(&self) -> Result<*mut c_void, ErrorStack> {
        let app_data: *mut c_void = unsafe { ffi::RSA_meth_get0_app_data(self.as_ptr()) };
        Ok(app_data)
    }

    #[corresponds(RSA_meth_set0_app_data)]
    #[inline]
    pub fn set_app_data(&self, app_data: *mut c_void) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set0_app_data(self.as_ptr(), app_data))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_pub_enc)]
    #[inline]
    pub fn set_pub_enc(
        &self,
        pub_enc: extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_pub_enc(self.as_ptr(), pub_enc))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_pub_dec)]
    #[inline]
    pub fn set_pub_dec(
        &self,
        pub_dec: extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_pub_dec(self.as_ptr(), pub_dec))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_priv_enc)]
    #[inline]
    pub fn set_priv_enc(
        &self,
        priv_enc: extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_priv_enc(self.as_ptr(), priv_enc))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_priv_dec)]
    #[inline]
    pub fn set_priv_dec(
        &self,
        priv_dec: extern "C" fn(
            flen: c_int,
            from: *const c_uchar,
            to: *mut c_uchar,
            rsa: *mut RSA,
            padding: c_int,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_priv_dec(self.as_ptr(), priv_dec))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_mod_exp)]
    #[inline]
    pub fn set_mod_exp(
        &self,
        mod_exp: extern "C" fn(
            r0: *mut BIGNUM,
            i: *const BIGNUM,
            rsa: *mut RSA,
            ctx: *mut BN_CTX,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_mod_exp(self.as_ptr(), mod_exp))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_bn_mod_exp)]
    #[inline]
    pub fn set_bn_mod_exp(
        &self,
        bn_mod_exp: extern "C" fn(
            r: *mut BIGNUM,
            a: *const BIGNUM,
            p: *const BIGNUM,
            m: *const BIGNUM,
            ctx: *mut BN_CTX,
            m_ctx: *mut BN_MONT_CTX,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_bn_mod_exp(self.as_ptr(), bn_mod_exp))?;
        }
        Ok(())
    }

    #[corresponds(RSA_met_set_init)]
    #[inline]
    pub fn set_init(&self, init: extern "C" fn(rsa: *mut RSA) -> c_int) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_init(self.as_ptr(), init))?;
        }
        Ok(())
    }

    #[corresponds(RSA_met_set_finish)]
    #[inline]
    pub fn set_finish(
        &self,
        finish: extern "C" fn(rsa: *mut RSA) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_finish(self.as_ptr(), finish))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_sign)]
    #[inline]
    pub fn set_sign(
        &self,
        sign: extern "C" fn(
            _type: c_int,
            m: *const c_uchar,
            m_length: c_uint,
            sigret: *mut c_uchar,
            siglen: *mut c_uint,
            rsa: *const RSA,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_sign(self.as_ptr(), sign))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_verify)]
    #[inline]
    pub fn set_verify(
        &self,
        verify: extern "C" fn(
            dtype: c_int,
            m: *const c_uchar,
            m_length: c_uint,
            sigbuf: *const c_uchar,
            siglen: c_uint,
            rsa: *const RSA,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_verify(self.as_ptr(), verify))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_keygen)]
    #[inline]
    pub fn set_keygen(
        &self,
        keygen: extern "C" fn(
            rsa: *mut RSA,
            bits: c_int,
            e: *mut BIGNUM,
            cb: *mut BN_GENCB,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_keygen(self.as_ptr(), keygen))?;
        }
        Ok(())
    }

    #[corresponds(RSA_meth_set_multi_prime_keygen)]
    #[inline]
    pub fn set_multi_prime_keygen(
        &self,
        keygen: extern "C" fn(
            rsa: *mut RSA,
            bits: c_int,
            primes: c_int,
            e: *mut BIGNUM,
            cb: *mut BN_GENCB,
        ) -> c_int,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::RSA_meth_set_multi_prime_keygen(self.as_ptr(), keygen))?;
        }
        Ok(())
    }
}

impl Drop for RsaMethod {
    fn drop(&mut self) {
        unsafe {
            ffi::RSA_meth_free(self.as_ptr());
        }
    }
}

impl Clone for RsaMethod {
    fn clone(&self) -> Self {
        self.duplicate().unwrap()
    }
}

mod test {
    use super::*;

    #[cfg(test)]
    fn rsa_method_test() {
        // Because there isn't a great way to test all of this RSA_METHOD functionality, what we
        // do here is setup function pointers in this test module, and we call all of the
        // RSA_METHOD functions as implemented above, simply to assert that everything
        // (getters/setters) work as expected.

        let name: &str = "TESTING RSA METHOD";

        let mut rsa_method = RsaMethod::new(name, 0);
        assert!(rsa_method.is_ok());
        let mut rsa_method = rsa_method.unwrap();

        rsa_method.clone();

        let expected_name = rsa_method.get_name().unwrap();
        assert_eq!(name, expected_name);

        {
            let new_name: &str = "NEW TESTING NAME";
            rsa_method.set_name(new_name).unwrap();
            let actual_new_name = rsa_method.get_name().unwrap();
            assert_eq!(new_name, actual_new_name);
        }

        {
            let new_flags: i32 = 0x00ff;
            rsa_method.set_flags(new_flags).unwrap();
            let actual_new_flags = rsa_method.get_flags().unwrap();
            assert_eq!(new_flags, actual_new_flags);
        }

        {
            let some_app_data: *mut c_void = 0x0900 as *mut c_void;
            rsa_method.set_app_data(some_app_data).unwrap();
            let actual_app_data = rsa_method.get_app_data().unwrap();
            assert_eq!(some_app_data, actual_app_data);
        }

        // test all of the setters - the dummy functions for here are set down below

        rsa_method.set_pub_enc(test_pub_enc).unwrap();
        rsa_method.set_pub_dec(test_pub_dec).unwrap();
        rsa_method.set_priv_enc(test_priv_enc);
        rsa_method.set_priv_dec(test_priv_dec);
        rsa_method.set_mod_exp(test_mod_exp);
        rsa_method.set_bn_mod_exp(test_bn_mod_exp);
        rsa_method.set_init(test_init);
        rsa_method.set_finish(test_finish);
        rsa_method.set_sign(test_sign);
        rsa_method.set_verify(test_verify);
        rsa_method.set_keygen(test_keygen);
        rsa_method.set_multi_prime_keygen(test_multi_prime_keygen);
    }

    #[no_mangle]
    extern "C" fn test_pub_enc(
        _flen: c_int,
        _from: *const c_uchar,
        _to: *mut c_uchar,
        _rsa: *mut RSA,
        _padding: c_int,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_pub_dec(
        _flen: c_int,
        _from: *const c_uchar,
        _to: *mut c_uchar,
        _rsa: *mut RSA,
        _padding: c_int,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_priv_enc(
        _flen: c_int,
        _from: *const c_uchar,
        _to: *mut c_uchar,
        _rsa: *mut RSA,
        _padding: c_int,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_priv_dec(
        _flen: c_int,
        _from: *const c_uchar,
        _to: *mut c_uchar,
        _rsa: *mut RSA,
        _padding: c_int,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_mod_exp(
        _r0: *mut BIGNUM,
        _i: *const BIGNUM,
        _rsa: *mut RSA,
        _ctx: *mut BN_CTX,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_bn_mod_exp(
        _r: *mut BIGNUM,
        _a: *const BIGNUM,
        _p: *const BIGNUM,
        _m: *const BIGNUM,
        _ctx: *mut BN_CTX,
        _m_ctx: *mut BN_MONT_CTX,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_init(_rsa: *mut RSA) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_finish(_rsa: *mut RSA) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_sign(
        _type: c_int,
        _m: *const c_uchar,
        _m_length: c_uint,
        _sigret: *mut c_uchar,
        _siglen: *mut c_uint,
        _rsa: *const RSA,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_verify(
        _dtype: c_int,
        _m: *const c_uchar,
        _m_length: c_uint,
        _sigbuf: *const c_uchar,
        _siglen: c_uint,
        _rsa: *const RSA,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_keygen(
        _rsa: *mut RSA,
        _bits: c_int,
        _e: *mut BIGNUM,
        _cb: *mut BN_GENCB,
    ) -> c_int {
        0
    }

    #[no_mangle]
    extern "C" fn test_multi_prime_keygen(
        _rsa: *mut RSA,
        _bits: c_int,
        _primes: c_int,
        _e: *mut BIGNUM,
        _cb: *mut BN_GENCB,
    ) -> c_int {
        0
    }
}
