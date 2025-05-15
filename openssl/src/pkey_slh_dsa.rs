//! Stateless hash-based digital signatures.
//!
//! SLH-DSA is a signature algorithm that is believed to be secure
//! against adversaries with quantum computers.  It has been
//! standardized by NIST as [FIPS 205].
//!
//! [FIPS 205]: https://csrc.nist.gov/pubs/fips/205/final

use std::ffi::CStr;

use foreign_types::ForeignType;
use libc::c_int;
use std::ptr;

use crate::error::ErrorStack;
use crate::ossl_param::{OsslParam, OsslParamBuilder};
use crate::pkey::{PKey, Private, Public};
use crate::pkey_ctx::PkeyCtx;
use crate::{cvt, cvt_p};
use openssl_macros::corresponds;

const OSSL_PKEY_PARAM_SEED: &[u8; 5] = b"seed\0";
const OSSL_PKEY_PARAM_PUB_KEY: &[u8; 4] = b"pub\0";
const OSSL_PKEY_PARAM_PRIV_KEY: &[u8; 5] = b"priv\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake192s,
    SlhDsaShake192f,
    SlhDsaShake256s,
    SlhDsaShake256f,
}

impl Variant {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Variant::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            Variant::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            Variant::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            Variant::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            Variant::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            Variant::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            Variant::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            Variant::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
            Variant::SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
            Variant::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
            Variant::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            Variant::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        }
    }

    pub(crate) fn as_cstr(&self) -> &'static CStr {
        match self {
            Variant::SlhDsaSha2_128s => CStr::from_bytes_with_nul(b"SLH-DSA-SHA2-128s\0"),
            Variant::SlhDsaSha2_128f => CStr::from_bytes_with_nul(b"SLH-DSA-SHA2-128f\0"),
            Variant::SlhDsaSha2_192s => CStr::from_bytes_with_nul(b"SLH-DSA-SHA2-192s\0"),
            Variant::SlhDsaSha2_192f => CStr::from_bytes_with_nul(b"SLH-DSA-SHA2-192f\0"),
            Variant::SlhDsaSha2_256s => CStr::from_bytes_with_nul(b"SLH-DSA-SHA2-256s\0"),
            Variant::SlhDsaSha2_256f => CStr::from_bytes_with_nul(b"SLH-DSA-SHA2-256f\0"),
            Variant::SlhDsaShake128s => CStr::from_bytes_with_nul(b"SLH-DSA-SHAKE-128s\0"),
            Variant::SlhDsaShake128f => CStr::from_bytes_with_nul(b"SLH-DSA-SHAKE-128f\0"),
            Variant::SlhDsaShake192s => CStr::from_bytes_with_nul(b"SLH-DSA-SHAKE-192s\0"),
            Variant::SlhDsaShake192f => CStr::from_bytes_with_nul(b"SLH-DSA-SHAKE-192f\0"),
            Variant::SlhDsaShake256s => CStr::from_bytes_with_nul(b"SLH-DSA-SHAKE-256s\0"),
            Variant::SlhDsaShake256f => CStr::from_bytes_with_nul(b"SLH-DSA-SHAKE-256f\0"),
        }
        .unwrap()
    }
}

pub struct PKeySlhDsaBuilder<T> {
    bld: OsslParamBuilder,
    variant: Variant,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeySlhDsaBuilder<T> {
    /// Creates a new `PKeySlhDsaBuilder` to build ML-DSA private or
    /// public keys.
    pub fn new(
        variant: Variant,
        public: &[u8],
        private: Option<&[u8]>,
    ) -> Result<PKeySlhDsaBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public)?;
        if let Some(private) = private {
            bld.add_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, private)?
        };
        Ok(PKeySlhDsaBuilder::<T> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Creates a new `PKeySlhDsaBuilder` to build ML-DSA private keys
    /// from a seed.
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<PKeySlhDsaBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_SEED, seed)?;
        Ok(PKeySlhDsaBuilder::<T> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Build PKey. Internal.
    #[corresponds(EVP_PKEY_fromdata)]
    fn build_internal(self, selection: c_int) -> Result<PKey<T>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, self.variant.as_str(), None)?;
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

impl PKeySlhDsaBuilder<Private> {
    /// Returns the Private ML-DSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Private>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_KEYPAIR)
    }

    /// Creates a new `PKeyRsaBuilder` to generate a new ML-DSA key
    /// pair.
    pub fn new_generate(variant: Variant) -> Result<PKeySlhDsaBuilder<Private>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        Ok(PKeySlhDsaBuilder::<Private> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Generate an ML-DSA PKey.
    pub fn generate(self) -> Result<PKey<Private>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, self.variant.as_str(), None)?;
        ctx.keygen_init()?;
        let params = self.bld.to_param()?;
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_params(ctx.as_ptr(), params.as_ptr()))?;
        }
        ctx.generate()
    }
}

impl PKeySlhDsaBuilder<Public> {
    /// Returns the Public ML-DSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Public>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

pub struct PKeySlhDsaParams<T> {
    params: OsslParam,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeySlhDsaParams<T> {
    /// Creates a new `PKeySlhDsaParams` from existing ML-DSA PKey. Internal.
    #[corresponds(EVP_PKEY_todata)]
    fn _new_from_pkey<S>(
        pkey: &PKey<S>,
        selection: c_int,
    ) -> Result<PKeySlhDsaParams<T>, ErrorStack> {
        unsafe {
            let mut params: *mut ffi::OSSL_PARAM = ptr::null_mut();
            cvt(ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params))?;
            Ok(PKeySlhDsaParams::<T> {
                params: OsslParam::from_ptr(params),
                _m: ::std::marker::PhantomData,
            })
        }
    }
}

impl PKeySlhDsaParams<Public> {
    /// Creates a new `PKeySlhDsaParams` from existing Public ML-DSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey<S>(pkey: &PKey<S>) -> Result<PKeySlhDsaParams<Public>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PUBLIC_KEY)
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        self.params
            .locate(OSSL_PKEY_PARAM_PUB_KEY)
            .unwrap()
            .get_octet_string()
    }
}

impl PKeySlhDsaParams<Private> {
    /// Creates a new `PKeySlhDsaParams` from existing Private ML-DSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Private>) -> Result<PKeySlhDsaParams<Private>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_KEYPAIR)
    }

    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_SEED)?.get_octet_string()
    }

    /// Returns the private key.
    pub fn private_key(&self) -> Result<&[u8], ErrorStack> {
        self.params
            .locate(OSSL_PKEY_PARAM_PRIV_KEY)?
            .get_octet_string()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::signature::Signature;

    #[test]
    fn test_generate_slh_dsa_sha2_128s() {
        test_generate(Variant::SlhDsaSha2_128s);
    }

    #[test]
    fn test_generate_slh_dsa_sha2_128f() {
        test_generate(Variant::SlhDsaSha2_128f);
    }

    #[test]
    fn test_generate_slh_dsa_sha2_192s() {
        test_generate(Variant::SlhDsaSha2_192s);
    }

    #[test]
    fn test_generate_slh_dsa_sha2_192f() {
        test_generate(Variant::SlhDsaSha2_192f);
    }

    #[test]
    fn test_generate_slh_dsa_sha2_256s() {
        test_generate(Variant::SlhDsaSha2_256s);
    }

    #[test]
    fn test_generate_slh_dsa_sha2_256f() {
        test_generate(Variant::SlhDsaSha2_256f);
    }

    #[test]
    fn test_generate_slh_dsa_shake_128s() {
        test_generate(Variant::SlhDsaShake128s);
    }

    #[test]
    fn test_generate_slh_dsa_shake_128f() {
        test_generate(Variant::SlhDsaShake128f);
    }

    #[test]
    fn test_generate_slh_dsa_shake_192s() {
        test_generate(Variant::SlhDsaShake192s);
    }

    #[test]
    fn test_generate_slh_dsa_shake_192f() {
        test_generate(Variant::SlhDsaShake192f);
    }

    #[test]
    fn test_generate_slh_dsa_shake_256s() {
        test_generate(Variant::SlhDsaShake256s);
    }

    #[test]
    fn test_generate_slh_dsa_shake_256f() {
        test_generate(Variant::SlhDsaShake256f);
    }

    fn test_generate(variant: Variant) {
        let bld = PKeySlhDsaBuilder::<Private>::new_generate(variant).unwrap();
        let key = bld.generate().unwrap();

        let mut algo = Signature::for_slh_dsa(variant).unwrap();

        let data = b"Some Crypto Text";
        let bad_data = b"Some Crypto text";

        let mut signature = vec![];
        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.sign_message_init(&mut algo).unwrap();
        ctx.sign_to_vec(&data[..], &mut signature).unwrap();

        // Verify good version with the original PKEY.
        ctx.verify_message_init(&mut algo).unwrap();
        let valid = ctx.verify(&data[..], &signature);
        assert!(matches!(valid, Ok(true)));
        assert!(ErrorStack::get().errors().is_empty());

        // Verify bad version with the original PKEY.
        ctx.verify_message_init(&mut algo).unwrap();
        let valid = ctx.verify(&bad_data[..], &signature);
        assert!(matches!(valid, Ok(false) | Err(_)));
        assert!(ErrorStack::get().errors().is_empty());

        // Derive a new PKEY with only the public bits.
        let public_params = PKeySlhDsaParams::<Public>::from_pkey(&key).unwrap();
        let key_pub =
            PKeySlhDsaBuilder::<Public>::new(variant, public_params.public_key().unwrap(), None)
                .unwrap()
                .build()
                .unwrap();
        let mut ctx = PkeyCtx::new(&key_pub).unwrap();
        let mut algo = Signature::for_slh_dsa(variant).unwrap();

        // Verify good version with the public PKEY.
        ctx.verify_message_init(&mut algo).unwrap();
        let valid = ctx.verify(&data[..], &signature);
        assert!(matches!(valid, Ok(true)));
        assert!(ErrorStack::get().errors().is_empty());

        // Verify bad version with the public PKEY.
        ctx.verify_message_init(&mut algo).unwrap();
        let valid = ctx.verify(&bad_data[..], &signature);
        assert!(matches!(valid, Ok(false) | Err(_)));
        assert!(ErrorStack::get().errors().is_empty());
    }
}
