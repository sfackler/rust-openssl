//! OSSL_PARAM management for OpenSSL 3.*
//!
//! The OSSL_PARAM structure represents generic attribute that can represent various
//! properties in OpenSSL, including keys and operations.
//!
//! For convinience, the OSSL_PARAM_BLD builder can be used to dynamically construct
//! these structure.
//!
//! Note, that this module is available only in OpenSSL 3.*
//!
//! # Example: Generate RSA Key
//!
//! let mut ctx = PkeyCtx::new_from_name(None, "RSA", None).unwrap();
//! ctx.keygen_init().unwrap();
//! let mut bld = OsslParamBuilder::new().unwrap();
//! bld.add_uint("bits\0", 3096).unwrap();
//! let params = bld.to_params().unwrap();
//! ctx.set_params(params).unwrap();
//! let key = ctx.generate().unwrap();
//!
use crate::bn::BigNumRef;
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
    pub fn locate(&self, key: &str) -> Result<&OsslParamRef, ErrorStack> {
        unsafe {
            let param = cvt_p(ffi::OSSL_PARAM_locate(
                self.as_ptr(),
                key.as_ptr() as *const c_char,
            ))?;
            Ok(OsslParamRef::from_ptr(param))
        }
    }

    /// Get `BigNumRef` from the current `OsslParam`
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn get_bn(&self) -> Result<&BigNumRef, ErrorStack> {
        unsafe {
            let mut bn: *mut ffi::BIGNUM = ptr::null_mut();
            cvt(ffi::OSSL_PARAM_get_BN(self.as_ptr(), &mut bn))?;
            Ok(BigNumRef::from_ptr(bn))
        }
    }

    /// Get `&str` from the current `OsslParam`
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
    pub fn to_params(self) -> Result<OsslParam, ErrorStack> {
        unsafe {
            let params = cvt_p(ffi::OSSL_PARAM_BLD_to_param(self.0))?;
            Ok(OsslParam::from_ptr(params))
        }
    }
}

impl OsslParamBuilderRef {
    /// Adds a `BigNum` to `OsslParamBuilder`.
    ///
    /// Note, that both key and bn need to exist until the `to_params` is called!
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    pub fn add_bn(&mut self, key: &str, bn: &BigNumRef) -> Result<(), ErrorStack> {
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
    /// Note, that both `key` and `buf` need to exist until the `to_params` is called!
    #[corresponds(OSSL_PARAM_BLD_push_utf8_string)]
    pub fn add_utf8_string(&mut self, key: &str, buf: &str) -> Result<(), ErrorStack> {
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
    /// Note, that both `key` and `buf` need to exist until the `to_params` is called!
    #[corresponds(OSSL_PARAM_BLD_push_octet_string)]
    pub fn add_octet_string(&mut self, key: &str, buf: &[u8]) -> Result<(), ErrorStack> {
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
    /// Note, that both `key` and `buf` need to exist until the `to_params` is called!
    #[corresponds(OSSL_PARAM_BLD_push_uint)]
    pub fn add_uint(&mut self, key: &str, val: u32) -> Result<(), ErrorStack> {
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

#[cfg(test)]
mod tests {

    use crate::ec::EcKey;
    use crate::error::Error;
    use crate::nid::Nid;
    use crate::pkey::{PKey, Private};
    use crate::pkey_ctx::PkeyCtx;
    use crate::rsa::Rsa;

    use super::*;

    #[test]
    fn test_build_pkey_rsa() {
        /* First, generate the key with old API */
        let rsa = Rsa::generate(2048).unwrap();
        let pkey1 = PKey::from_rsa(rsa.clone()).unwrap();

        /* Now, construct the OSSL_PARAM manually from the old key */
        let mut bld = OsslParamBuilder::new().unwrap();
        // TODO do we want a better API with the parameter names?
        bld.add_bn("n\0", rsa.n()).unwrap();
        bld.add_bn("e\0", rsa.e()).unwrap();
        bld.add_bn("d\0", rsa.d()).unwrap();
        bld.add_bn("rsa-factor1\0", rsa.p().unwrap()).unwrap();
        bld.add_bn("rsa-factor2\0", rsa.q().unwrap()).unwrap();
        bld.add_bn("rsa-exponent1\0", rsa.dmp1().unwrap()).unwrap();
        bld.add_bn("rsa-exponent2\0", rsa.dmq1().unwrap()).unwrap();
        bld.add_bn("rsa-coefficient1\0", rsa.iqmp().unwrap())
            .unwrap();
        let params = bld.to_params().unwrap();

        let mut ctx = PkeyCtx::new_from_name(None, "RSA", None).unwrap();
        ctx.fromdata_init().unwrap();
        let pkey2 = PKey::<Private>::fromdata(ctx, params).unwrap();

        /* Verify it works the same way as the old one */
        assert!(pkey1.public_eq(&pkey2));
        assert!(Error::get().is_none());

        // FIXME use of ffi in test is not intended -- we will need some constants
        let params = pkey2.todata(ffi::EVP_PKEY_KEYPAIR).unwrap();
        assert_eq!(params.locate("n\0").unwrap().get_bn().unwrap(), rsa.n());
        assert_eq!(params.locate("e\0").unwrap().get_bn().unwrap(), rsa.e());
        assert_eq!(params.locate("d\0").unwrap().get_bn().unwrap(), rsa.d());
        assert_eq!(
            params.locate("rsa-factor1\0").unwrap().get_bn().unwrap(),
            rsa.p().unwrap()
        );
        assert_eq!(
            params.locate("rsa-factor2\0").unwrap().get_bn().unwrap(),
            rsa.q().unwrap()
        );
        assert_eq!(
            params.locate("rsa-exponent1\0").unwrap().get_bn().unwrap(),
            rsa.dmp1().unwrap()
        );
        assert_eq!(
            params.locate("rsa-exponent2\0").unwrap().get_bn().unwrap(),
            rsa.dmq1().unwrap()
        );
        assert_eq!(
            params
                .locate("rsa-coefficient1\0")
                .unwrap()
                .get_bn()
                .unwrap(),
            rsa.iqmp().unwrap()
        );
    }

    #[test]
    fn test_build_pkey_ecdsa() {
        use crate::bn::BigNumContext;
        use crate::ec::PointConversionForm;

        /* First, generate the key with old API */
        let group = crate::ec::EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey1 = PKey::from_ec_key(ec_key.clone()).unwrap();

        /* is there a better way? */
        let mut ctx = BigNumContext::new().unwrap();
        let pubkey = ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        /* Now, construct the OSSL_PARAM manually from the old key */
        let mut bld = OsslParamBuilder::new().unwrap();
        // TODO do we want a better API with the parameter names?
        bld.add_utf8_string("group\0", "secp256k1").unwrap();
        bld.add_octet_string("pub\0", pubkey.as_slice()).unwrap();
        bld.add_bn("priv\0", ec_key.private_key()).unwrap();
        let params = bld.to_params().unwrap();

        /* Build new key */
        let mut ctx = PkeyCtx::new_from_name(None, "EC", None).unwrap();
        ctx.fromdata_init().unwrap();
        let pkey2 = PKey::<Private>::fromdata(ctx, params).unwrap();

        /* Verify it works the same way as the old one */
        assert!(pkey1.public_eq(&pkey2));
        assert!(Error::get().is_none());

        // FIXME use of ffi in test is not intended -- we will need some constants
        let params = pkey2.todata(ffi::EVP_PKEY_KEYPAIR).unwrap();
        assert_eq!(
            params.locate("priv\0").unwrap().get_bn().unwrap(),
            ec_key.private_key()
        );
        assert_eq!(
            params.locate("group\0").unwrap().get_utf8_string().unwrap(),
            "secp256k1"
        );
        assert_eq!(
            params.locate("pub\0").unwrap().get_octet_string().unwrap(),
            pubkey.as_slice()
        );
    }

    #[test]
    fn test_generate_rsa() {
        use crate::pkey::Id;

        let mut ctx = PkeyCtx::new_from_name(None, "RSA", None).unwrap();
        ctx.keygen_init().unwrap();

        let mut bld = OsslParamBuilder::new().unwrap();
        bld.add_uint("bits\0", 3096).unwrap();
        let params = bld.to_params().unwrap();
        ctx.set_params(params).unwrap();
        let key = ctx.generate().unwrap();

        assert_eq!(key.id(), Id::RSA);
        assert!(key.dsa().is_err());

        let rsa = key.rsa().unwrap();
        // FIXME use of ffi in test is not intended -- we will need some constants
        let params = key.todata(ffi::EVP_PKEY_KEYPAIR).unwrap();
        assert_eq!(rsa.e(), params.locate("e\0").unwrap().get_bn().unwrap());
        assert_eq!(rsa.n(), params.locate("n\0").unwrap().get_bn().unwrap());
        assert_eq!(rsa.d(), params.locate("d\0").unwrap().get_bn().unwrap());
        assert_eq!(
            rsa.p().unwrap(),
            params.locate("rsa-factor1\0").unwrap().get_bn().unwrap()
        );
        assert_eq!(
            rsa.q().unwrap(),
            params.locate("rsa-factor2\0").unwrap().get_bn().unwrap()
        );
    }
}
