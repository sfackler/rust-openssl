//! Elliptic Curve using OpenSSL 3.* API
//!
//! Cryptography relies on the difficulty of solving mathematical problems, such as the factor
//! of large integers composed of two large prime numbers and the discrete logarithm of a
//! random elliptic curve.  This module provides low-level features of the latter.
//! Elliptic Curve protocols can provide the same security with smaller keys.

use foreign_types::ForeignType;
use libc::c_int;
use std::ptr;

use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::ossl_param::{OsslParam, OsslParamBuilder};
use crate::pkey::{PKey, Private, Public};
use crate::pkey_ctx::PkeyCtx;
use crate::{cvt, cvt_p};
use openssl_macros::corresponds;

const OSSL_PKEY_PARAM_GROUP_NAME: &[u8; 6] = b"group\0";
const OSSL_PKEY_PARAM_PUB_KEY: &[u8; 4] = b"pub\0";
const OSSL_PKEY_PARAM_PRIV_KEY: &[u8; 5] = b"priv\0";

pub struct PKeyEcdsaBuilder<T> {
    bld: OsslParamBuilder,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyEcdsaBuilder<T> {
    /// Creates a new `PKeyEcdsaBuilder` to build ECDSA private or public keys.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent and `d` is the private exponent.
    ///
    pub fn new(
        group: &str,
        point: &[u8],
        private: Option<&BigNumRef>,
    ) -> Result<PKeyEcdsaBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group)?;
        bld.add_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point)?;
        if let Some(private) = private {
            bld.add_bn(OSSL_PKEY_PARAM_PRIV_KEY, private)?
        };
        Ok(PKeyEcdsaBuilder::<T> {
            bld,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Build PKey. Internal.
    #[corresponds(EVP_PKEY_fromdata)]
    fn build_internal(self, selection: c_int) -> Result<PKey<T>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, "EC", None)?;
        ctx.fromdata_init()?;
        let params = self.bld.to_param()?;
        unsafe {
            let evp = cvt_p(ffi::EVP_PKEY_new())?;
            let pkey = PKey::from_ptr(evp);
            cvt(ffi::EVP_PKEY_fromdata(
                ctx.as_ptr(),
                &mut pkey.as_ptr(),
                selection,
                params.as_ptr(),
            ))?;
            Ok(pkey)
        }
    }
}

impl PKeyEcdsaBuilder<Private> {
    /// Returns the Private ECDSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Private>, ErrorStack> {
        /* The ECDSA requires here a keypair as the private key does not work without public point! */
        self.build_internal(ffi::EVP_PKEY_KEYPAIR)
    }
}

impl PKeyEcdsaBuilder<Public> {
    /// Returns the Public ECDSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Public>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

pub struct PKeyEcdsaParams<T> {
    params: OsslParam,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyEcdsaParams<T> {
    /// Creates a new `PKeyEcdsaParams` from existing ECDSA PKey. Internal.
    #[corresponds(EVP_PKEY_todata)]
    fn _new_from_pkey(pkey: &PKey<T>, selection: c_int) -> Result<PKeyEcdsaParams<T>, ErrorStack> {
        unsafe {
            let mut params: *mut ffi::OSSL_PARAM = ptr::null_mut();
            cvt(ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params))?;
            Ok(PKeyEcdsaParams::<T> {
                params: OsslParam::from_ptr(params),
                _m: ::std::marker::PhantomData,
            })
        }
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        self.params
            .locate(OSSL_PKEY_PARAM_PUB_KEY)?
            .get_octet_string()
    }

    /// Returns a reference to a group name
    pub fn group(&self) -> Result<&str, ErrorStack> {
        self.params
            .locate(OSSL_PKEY_PARAM_GROUP_NAME)?
            .get_utf8_string()
    }
}

impl PKeyEcdsaParams<Public> {
    /// Creates a new `PKeyEcdsaParams` from existing Public ECDSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Public>) -> Result<PKeyEcdsaParams<Public>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

impl PKeyEcdsaParams<Private> {
    /// Creates a new `PKeyEcdsaParams` from existing Private ECDSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Private>) -> Result<PKeyEcdsaParams<Private>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_KEYPAIR)
    }

    /// Returns the private key.
    pub fn private_key(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_PRIV_KEY)?.get_bn()
    }
}

#[cfg(test)]
mod tests {

    use crate::bn::BigNumContext;
    use crate::ec::{EcKey, PointConversionForm};
    use crate::error::Error;
    use crate::nid::Nid;

    use super::*;

    #[test]
    fn test_build_pkey_ecdsa_private() {
        /* First, generate the key with old API */
        let nid: Nid = Nid::SECP256K1;
        let curve_name = nid.short_name().unwrap();
        let group = crate::ec::EcGroup::from_curve_name(nid).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey1 = PKey::from_ec_key(ec_key.clone()).unwrap();

        /* Now, build the new PKey from the old key with new API */
        let mut ctx = BigNumContext::new().unwrap();
        let pubkey = ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let bld = PKeyEcdsaBuilder::<Private>::new(curve_name, &pubkey, Some(ec_key.private_key()))
            .unwrap();
        let pkey2 = bld.build().unwrap();

        /* Verify it works the same way as the old one */
        assert!(pkey1.public_eq(&pkey2));
        assert!(Error::get().is_none());

        let params = PKeyEcdsaParams::<Private>::from_pkey(&pkey2).unwrap();
        assert_eq!(params.group().unwrap(), curve_name);
        assert_eq!(&params.private_key().unwrap(), ec_key.private_key());
        assert_eq!(params.public_key().unwrap(), pubkey);
    }

    #[test]
    fn test_build_pkey_ecdsa_public() {
        /* First, generate the key with old API */
        let nid: Nid = Nid::SECP256K1;
        let curve_name = nid.short_name().unwrap();
        let group = crate::ec::EcGroup::from_curve_name(nid).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey1 = PKey::from_ec_key(ec_key.clone()).unwrap();

        /* Now, build the new PKey from the old key with new API */
        let mut ctx = BigNumContext::new().unwrap();
        let pubkey = ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let bld = PKeyEcdsaBuilder::<Public>::new(curve_name, &pubkey, None).unwrap();
        let pkey2 = bld.build().unwrap();

        /* Verify it works the same way as the old one */
        assert!(pkey1.public_eq(&pkey2));
        assert!(Error::get().is_none());

        let params = PKeyEcdsaParams::<Public>::from_pkey(&pkey2).unwrap();
        assert_eq!(params.group().unwrap(), curve_name);
        assert_eq!(params.public_key().unwrap(), pubkey);
    }
}
