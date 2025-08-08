//! Rivest–Shamir–Adleman cryptosystem used through the OpenSSL 3.* API
//!
//! RSA is one of the earliest asymmetric public key encryption schemes.
//! Like many other cryptosystems, RSA relies on the presumed difficulty of a hard
//! mathematical problem, namely factorization of the product of two large prime
//! numbers. At the moment there does not exist an algorithm that can factor such
//! large numbers in reasonable time. RSA is used in a wide variety of
//! applications including digital signatures and key exchanges such as
//! establishing a TLS/SSL connection.
//!
//! The RSA acronym is derived from the first letters of the surnames of the
//! algorithm's founding trio.
//!
//! # Example
//!
//! Generate a 3096-bit RSA key pair and use the public key to encrypt some data.
//!
//! ```rust
//! use openssl::pkey::{PKey, Private};
//! use openssl::pkey_ctx::PkeyCtx;
//! use openssl::pkey_rsa::PKeyRsaBuilder;
//!
//! let bld = PKeyRsaBuilder::<Private>::new_generate(3096, None).unwrap();
//! let key = bld.generate().unwrap();
//!
//! let mut ctx = PkeyCtx::new(&key).unwrap();
//! ctx.encrypt_init().unwrap();
//!
//! let data = b"Some Crypto Text";
//! let mut ciphertext = vec![];
//! ctx.encrypt_to_vec(data, &mut ciphertext).unwrap();
//! ```

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

const OSSL_PKEY_PARAM_RSA_BITS: &[u8; 5] = b"bits\0";

const OSSL_PKEY_PARAM_RSA_N: &[u8; 2] = b"n\0";
const OSSL_PKEY_PARAM_RSA_E: &[u8; 2] = b"e\0";
const OSSL_PKEY_PARAM_RSA_D: &[u8; 2] = b"d\0";
const OSSL_PKEY_PARAM_RSA_FACTOR1: &[u8; 12] = b"rsa-factor1\0";
const OSSL_PKEY_PARAM_RSA_FACTOR2: &[u8; 12] = b"rsa-factor2\0";
const OSSL_PKEY_PARAM_RSA_EXPONENT1: &[u8; 14] = b"rsa-exponent1\0";
const OSSL_PKEY_PARAM_RSA_EXPONENT2: &[u8; 14] = b"rsa-exponent2\0";
const OSSL_PKEY_PARAM_RSA_COEFFICIENT1: &[u8; 17] = b"rsa-coefficient1\0";

pub struct PKeyRsaBuilder<T> {
    bld: OsslParamBuilder,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyRsaBuilder<T> {
    /// Creates a new `PKeyRsaBuilder` to build RSA private or public keys.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent and `d` is the private exponent.
    ///
    pub fn new(
        n: &BigNumRef,
        e: &BigNumRef,
        d: Option<&BigNumRef>,
    ) -> Result<PKeyRsaBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_bn(OSSL_PKEY_PARAM_RSA_N, n)?;
        bld.add_bn(OSSL_PKEY_PARAM_RSA_E, e)?;
        if let Some(d) = d {
            bld.add_bn(OSSL_PKEY_PARAM_RSA_D, d)?
        };
        Ok(PKeyRsaBuilder::<T> {
            bld,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Sets the factors of the private Rsa key for the builder.
    ///
    /// `p` and `q` are the first and second factors of `n`.
    pub fn set_factors(
        self,
        p: &BigNumRef,
        q: &BigNumRef,
    ) -> Result<PKeyRsaBuilder<T>, ErrorStack> {
        self.bld.add_bn(OSSL_PKEY_PARAM_RSA_FACTOR1, p)?;
        self.bld.add_bn(OSSL_PKEY_PARAM_RSA_FACTOR2, q)?;
        Ok(self)
    }

    /// Sets the Chinese Remainder Theorem params of the private Rsa key.
    ///
    /// `dmp1`, `dmq1`, and `iqmp` are the exponents and coefficient for
    /// CRT calculations which is used to speed up RSA operations.
    pub fn set_crt_params(
        self,
        dmp1: &BigNumRef,
        dmq1: &BigNumRef,
        iqmp: &BigNumRef,
    ) -> Result<PKeyRsaBuilder<T>, ErrorStack> {
        self.bld.add_bn(OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1)?;
        self.bld.add_bn(OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1)?;
        self.bld.add_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp)?;
        Ok(self)
    }

    /// Build PKey. Internal.
    #[corresponds(EVP_PKEY_fromdata)]
    fn build_internal(self, selection: c_int) -> Result<PKey<T>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
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

impl PKeyRsaBuilder<Private> {
    /// Returns the Private RSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Private>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PRIVATE_KEY)
    }

    /// Creates a new `PKeyRsaBuilder` to generate a new RSA key pair
    ///
    pub fn new_generate(bits: u32, e: Option<u32>) -> Result<PKeyRsaBuilder<Private>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_uint(OSSL_PKEY_PARAM_RSA_BITS, bits)?;
        if let Some(e) = e {
            bld.add_uint(OSSL_PKEY_PARAM_RSA_E, e)?
        };
        Ok(PKeyRsaBuilder::<Private> {
            bld,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Generate RSA PKey.
    pub fn generate(self) -> Result<PKey<Private>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
        ctx.keygen_init()?;
        let params = self.bld.to_param()?;
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_params(ctx.as_ptr(), params.as_ptr()))?;
        }
        ctx.generate()
    }
}

impl PKeyRsaBuilder<Public> {
    /// Builds the Public RSA PKey from the provideded parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Public>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

pub struct PKeyRsaParams<T> {
    params: OsslParam,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyRsaParams<T> {
    /// Creates a new `PKeyRsaParams` from existing RSA PKey. Internal.
    #[corresponds(EVP_PKEY_todata)]
    fn _new_from_pkey(pkey: &PKey<T>, selection: c_int) -> Result<PKeyRsaParams<T>, ErrorStack> {
        unsafe {
            let mut params: *mut ffi::OSSL_PARAM = ptr::null_mut();
            cvt(ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params))?;
            Ok(PKeyRsaParams::<T> {
                params: OsslParam::from_ptr(params),
                _m: ::std::marker::PhantomData,
            })
        }
    }

    /// Returns the modulus of the key.
    pub fn n(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_RSA_N)?.get_bn()
    }

    /// Returns the public exponent of the key.
    pub fn e(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_RSA_E)?.get_bn()
    }
}

impl PKeyRsaParams<Private> {
    /// Creates a new `PKeyRsaParams` from existing Private RSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Private>) -> Result<PKeyRsaParams<Private>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PRIVATE_KEY)
    }

    /// Returns the private exponent of the key.
    pub fn d(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_RSA_D)?.get_bn()
    }

    /// Returns the first factor of the exponent of the key.
    pub fn p(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_RSA_FACTOR1)?.get_bn()
    }

    /// Returns the second factor of the exponent of the key.
    pub fn q(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_RSA_FACTOR2)?.get_bn()
    }

    /// Returns the first exponent used for CRT calculations.
    pub fn dmp1(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_RSA_EXPONENT1)?.get_bn()
    }

    /// Returns the second exponent used for CRT calculations.
    pub fn dmq1(&self) -> Result<BigNum, ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_RSA_EXPONENT2)?.get_bn()
    }

    /// Returns the coefficient used for CRT calculations.
    pub fn iqmp(&self) -> Result<BigNum, ErrorStack> {
        self.params
            .locate(OSSL_PKEY_PARAM_RSA_COEFFICIENT1)?
            .get_bn()
    }
}

impl PKeyRsaParams<Public> {
    /// Creates a new `PKeyRsaParams` from existing Public RSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Public>) -> Result<PKeyRsaParams<Public>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

#[cfg(test)]
mod tests {

    use crate::error::Error;
    use crate::rsa::Rsa;

    use super::*;

    #[test]
    fn test_build_pkey_rsa_private() {
        /* First, generate the key with old API */
        let rsa = Rsa::generate(2048).unwrap();
        let pkey1 = PKey::from_rsa(rsa.clone()).unwrap();

        /* Now, build the new PKey from the old key with new API */
        let bld = PKeyRsaBuilder::<Private>::new(rsa.n(), rsa.e(), Some(rsa.d()))
            .unwrap()
            .set_factors(rsa.p().unwrap(), rsa.q().unwrap())
            .unwrap()
            .set_crt_params(
                rsa.dmp1().unwrap(),
                rsa.dmq1().unwrap(),
                rsa.iqmp().unwrap(),
            )
            .unwrap();
        let pkey2 = bld.build().unwrap();

        /* Verify it works the same way as the old one */
        assert!(pkey1.public_eq(&pkey2));
        assert!(Error::get().is_none());

        let params = PKeyRsaParams::<Private>::from_pkey(&pkey2).unwrap();
        assert_eq!(&params.n().unwrap(), rsa.n());
        assert_eq!(&params.e().unwrap(), rsa.e());
        assert_eq!(&params.d().unwrap(), rsa.d());
        assert_eq!(&params.p().unwrap(), rsa.p().unwrap());
        assert_eq!(&params.q().unwrap(), rsa.q().unwrap());
        assert_eq!(&params.dmp1().unwrap(), rsa.dmp1().unwrap());
        assert_eq!(&params.dmq1().unwrap(), rsa.dmq1().unwrap());
        assert_eq!(&params.iqmp().unwrap(), rsa.iqmp().unwrap());
    }

    #[test]
    fn test_build_pkey_rsa_public() {
        /* First, generate the key with old API */
        let rsa = Rsa::generate(2048).unwrap();
        let pkey1 = PKey::from_rsa(rsa.clone()).unwrap();

        /* Now, build the new public PKey from the old key with new API */
        let bld = PKeyRsaBuilder::<Public>::new(rsa.n(), rsa.e(), None).unwrap();
        let pkey2 = bld.build().unwrap();

        /* Verify it works the same way as the old one */
        assert!(pkey1.public_eq(&pkey2));
        assert!(Error::get().is_none());

        let params = PKeyRsaParams::<Public>::from_pkey(&pkey2).unwrap();
        assert_eq!(&params.n().unwrap(), rsa.n());
        assert_eq!(&params.e().unwrap(), rsa.e());
    }

    #[test]
    fn test_generate_rsa() {
        let bld = PKeyRsaBuilder::<Private>::new_generate(3096, None).unwrap();
        let key = bld.generate().unwrap();

        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.encrypt_init().unwrap();
        let pt = "Some Crypto Text".as_bytes();
        let mut ct = vec![];
        ctx.encrypt_to_vec(pt, &mut ct).unwrap();

        ctx.decrypt_init().unwrap();
        let mut out = vec![];
        ctx.decrypt_to_vec(&ct, &mut out).unwrap();

        assert_eq!(pt, out);
    }
}
