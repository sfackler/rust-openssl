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
//! Generate a 2048-bit RSA key pair and use the public key to encrypt some data.
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

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_int, c_uint};
use std::ptr;

use crate::bn::BigNumRef;
use crate::error::ErrorStack;
use crate::pkey::{PKey, Private, Public};
use crate::pkey_ctx::PkeyCtx;
use crate::{cvt, cvt_p};
use openssl_macros::corresponds;

pub const OSSL_PKEY_PARAM_RSA_BITS: &[u8; 5] = b"bits\0";

const OSSL_PKEY_PARAM_RSA_N: &[u8; 2] = b"n\0";
const OSSL_PKEY_PARAM_RSA_E: &[u8; 2] = b"e\0";
const OSSL_PKEY_PARAM_RSA_D: &[u8; 2] = b"d\0";
const OSSL_PKEY_PARAM_RSA_FACTOR1: &[u8; 12] = b"rsa-factor1\0";
const OSSL_PKEY_PARAM_RSA_FACTOR2: &[u8; 12] = b"rsa-factor2\0";
const OSSL_PKEY_PARAM_RSA_EXPONENT1: &[u8; 14] = b"rsa-exponent1\0";
const OSSL_PKEY_PARAM_RSA_EXPONENT2: &[u8; 14] = b"rsa-exponent2\0";
const OSSL_PKEY_PARAM_RSA_COEFFICIENT1: &[u8; 17] = b"rsa-coefficient1\0";

pub struct PKeyRsaBuilder<T> {
    bld: *mut ffi::OSSL_PARAM_BLD,
    _pkey: Option<PKey<T>>,
    params: *mut ffi::OSSL_PARAM,
}

impl<T> PKeyRsaBuilder<T> {
    /// Creates a new `PKeyRsaBuilder` to build RSA private or public keys.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent and `d` is the private exponent.
    ///
    #[corresponds(OSSL_PARAM_BLD_new)]
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    pub fn new(
        n: &BigNumRef,
        e: &BigNumRef,
        d: Option<&BigNumRef>,
    ) -> Result<PKeyRsaBuilder<T>, ErrorStack> {
        unsafe {
            ffi::init();

            let bld = cvt_p(ffi::OSSL_PARAM_BLD_new())?;
            let builder = PKeyRsaBuilder::<T> {
                bld,
                _pkey: None,
                params: ptr::null_mut(),
            };
            builder._add_bn(OSSL_PKEY_PARAM_RSA_N, n)?;
            builder._add_bn(OSSL_PKEY_PARAM_RSA_E, e)?;
            if let Some(d) = d {
                builder._add_bn(OSSL_PKEY_PARAM_RSA_D, d)?
            };
            Ok(builder)
        }
    }

    /// Creates a new `PKeyRsaBuilder` from existing RSA PKey. Internal.
    #[corresponds(EVP_PKEY_todata)]
    fn _new_from_pkey(pkey: &PKey<T>, selection: c_int) -> Result<PKeyRsaBuilder<T>, ErrorStack> {
        unsafe {
            ffi::init();

            let mut params: *mut ffi::OSSL_PARAM = ptr::null_mut();
            cvt(ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params))?;
            Ok(PKeyRsaBuilder::<T> {
                bld: ptr::null_mut(),
                _pkey: None,
                params,
            })
        }
    }

    /// Adds a `BigNum` to `PKeyRsaBuilder`. Internal
    ///
    /// Note, that both key and bn need to exist until the `to_params` is called!
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    fn _add_bn(&self, key: &[u8], bn: &BigNumRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_BN(
                self.bld,
                key.as_ptr() as *const c_char,
                bn.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Adds a unsigned int to `PKeyRsaBuilder`. Internal
    ///
    /// Note, that both `key` and `buf` need to exist until the `to_params` is called!
    #[corresponds(OSSL_PARAM_BLD_push_uint)]
    fn _add_uint(&self, key: &[u8], val: u32) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::OSSL_PARAM_BLD_push_uint(
                self.bld,
                key.as_ptr() as *const c_char,
                val as c_uint,
            ))
            .map(|_| ())
        }
    }

    /// Sets the factors of the private Rsa key for the builder.
    ///
    /// `p` and `q` are the first and second factors of `n`.
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    pub fn set_factors(
        self,
        p: &BigNumRef,
        q: &BigNumRef,
    ) -> Result<PKeyRsaBuilder<T>, ErrorStack> {
        self._add_bn(OSSL_PKEY_PARAM_RSA_FACTOR1, p)?;
        self._add_bn(OSSL_PKEY_PARAM_RSA_FACTOR2, q)?;
        Ok(self)
    }

    /// Sets the Chinese Remainder Theorem params of the private Rsa key.
    ///
    /// `dmp1`, `dmq1`, and `iqmp` are the exponents and coefficient for
    /// CRT calculations which is used to speed up RSA operations.
    #[corresponds(OSSL_PARAM_BLD_push_BN)]
    pub fn set_crt_params(
        self,
        dmp1: &BigNumRef,
        dmq1: &BigNumRef,
        iqmp: &BigNumRef,
    ) -> Result<PKeyRsaBuilder<T>, ErrorStack> {
        self._add_bn(OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1)?;
        self._add_bn(OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1)?;
        self._add_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp)?;
        Ok(self)
    }

    /// Build PKey. Internal.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    #[corresponds(EVP_PKEY_fromdata)]
    fn build_internal(self, selection: c_int) -> Result<PKey<T>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
        ctx.fromdata_init()?;
        unsafe {
            let params = cvt_p(ffi::OSSL_PARAM_BLD_to_param(self.bld))?;
            let evp = cvt_p(ffi::EVP_PKEY_new())?;
            let pkey = PKey::from_ptr(evp);
            cvt(ffi::EVP_PKEY_fromdata(
                ctx.as_ptr(),
                &mut pkey.as_ptr(),
                selection,
                params,
            ))?;
            Ok(pkey)
        }
    }

    /// Returns a reference to a BN from params.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    fn _get_bn(&self, key: &[u8]) -> Result<&BigNumRef, ErrorStack> {
        unsafe {
            let param = cvt_p(ffi::OSSL_PARAM_locate(
                self.params,
                key.as_ptr() as *const c_char,
            ))?;
            let mut bn: *mut ffi::BIGNUM = ptr::null_mut();
            cvt(ffi::OSSL_PARAM_get_BN(param, &mut bn))?;
            Ok(BigNumRef::from_ptr(bn))
        }
    }

    /// Returns a reference to the modulus of the key.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn n(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_N)
    }

    /// Returns a reference to the public exponent of the key.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn e(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_E)
    }
}

impl PKeyRsaBuilder<Private> {
    /// Returns the Private RSA PKey from the provided parameters.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Private>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PRIVATE_KEY)
    }

    /// Creates a new `PKeyRsaBuilder` to generate a new RSA key pair
    ///
    #[corresponds(OSSL_PARAM_BLD_new)]
    pub fn new_generate(bits: u32, e: Option<u32>) -> Result<PKeyRsaBuilder<Private>, ErrorStack> {
        unsafe {
            ffi::init();

            let bld = cvt_p(ffi::OSSL_PARAM_BLD_new())?;
            let builder = PKeyRsaBuilder::<Private> {
                bld: bld,
                _pkey: None,
                params: ptr::null_mut(),
            };
            builder._add_uint(OSSL_PKEY_PARAM_RSA_BITS, bits)?;
            if let Some(e) = e {
                builder._add_uint(OSSL_PKEY_PARAM_RSA_E, e)?
            };
            Ok(builder)
        }
    }

    /// Generate RSA PKey.
    pub fn generate(self) -> Result<PKey<Private>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
        ctx.keygen_init()?;
        unsafe {
            let params = cvt_p(ffi::OSSL_PARAM_BLD_to_param(self.bld))?;
            cvt(ffi::EVP_PKEY_CTX_set_params(ctx.as_ptr(), params))?;
        }
        ctx.generate()
    }

    /// Creates a new `PKeyRsaBuilder` from existing Private RSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn new_from_pkey(pkey: &PKey<Private>) -> Result<PKeyRsaBuilder<Private>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PRIVATE_KEY)
    }

    /// Returns a reference to the private exponent of the key.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn d(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_D)
    }

    /// Returns a reference to the first factor of the exponent of the key.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn p(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_FACTOR1)
    }

    /// Returns a reference to the second factor of the exponent of the key.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn q(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_FACTOR2)
    }

    /// Returns a reference to the first exponent used for CRT calculations.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn dmp1(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_EXPONENT1)
    }

    /// Returns a reference to the second exponent used for CRT calculations.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn dmq1(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_EXPONENT2)
    }

    /// Returns a reference to the coefficient used for CRT calculations.
    #[corresponds(OSSL_PARAM_locate)]
    #[corresponds(OSSL_PARAM_get_BN)]
    pub fn iqmp(&self) -> Result<&BigNumRef, ErrorStack> {
        self._get_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT1)
    }
}

impl PKeyRsaBuilder<Public> {
    /// Builds the Public RSA PKey from the provideded parameters.
    #[corresponds(OSSL_PARAM_BLD_to_param)]
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Public>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PUBLIC_KEY)
    }

    /// Creates a new `PKeyRsaBuilder` from existing Public RSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn new_from_pkey(pkey: &PKey<Public>) -> Result<PKeyRsaBuilder<Public>, ErrorStack> {
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

        let bld2 = PKeyRsaBuilder::<Private>::new_from_pkey(&pkey2).unwrap();
        assert_eq!(bld2.n().unwrap(), rsa.n());
        assert_eq!(bld2.e().unwrap(), rsa.e());
        assert_eq!(bld2.d().unwrap(), rsa.d());
        assert_eq!(bld2.p().unwrap(), rsa.p().unwrap());
        assert_eq!(bld2.q().unwrap(), rsa.q().unwrap());
        assert_eq!(bld2.dmp1().unwrap(), rsa.dmp1().unwrap());
        assert_eq!(bld2.dmq1().unwrap(), rsa.dmq1().unwrap());
        assert_eq!(bld2.iqmp().unwrap(), rsa.iqmp().unwrap());
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

        let bld2 = PKeyRsaBuilder::<Public>::new_from_pkey(&pkey2).unwrap();
        assert_eq!(bld2.n().unwrap(), rsa.n());
        assert_eq!(bld2.e().unwrap(), rsa.e());
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
