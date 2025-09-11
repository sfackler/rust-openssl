//! Module-Lattice-Based Digital Signatures.
//!
//! ML-DSA is a signature algorithm that is believed to be secure
//! against adversaries with quantum computers. It has been
//! standardized by NIST as [FIPS 204].
//!
//! [FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final

use crate::error::ErrorStack;
use crate::ossl_param::{OsslParamArray, OsslParamBuilder};
use crate::pkey::{PKey, Private, Public};
use crate::pkey_ctx::PkeyCtx;
use crate::{cvt, cvt_p};
use foreign_types::ForeignType;
use libc::c_int;
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr;

// Safety: these all have null terminators.
// We cen remove these CStr::from_bytes_with_nul_unchecked calls
// when we upgrade to Rust 1.77+ with literal c"" syntax.

const OSSL_PKEY_PARAM_SEED: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"seed\0") };
const OSSL_PKEY_PARAM_PUB_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"pub\0") };
const OSSL_PKEY_PARAM_PRIV_KEY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"priv\0") };
const MLDSA44_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"ML-DSA-44\0") };
const MLDSA65_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"ML-DSA-65\0") };
const MLDSA87_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"ML-DSA-87\0") };

const MLDSA44_STR: &str = "ML-DSA-44";
const MLDSA65_STR: &str = "ML-DSA-65";
const MLDSA87_STR: &str = "ML-DSA-87";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Variant {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Variant::MlDsa44 => MLDSA44_STR,
            Variant::MlDsa65 => MLDSA65_STR,
            Variant::MlDsa87 => MLDSA87_STR,
        }
    }

    pub(crate) fn as_cstr(&self) -> &'static CStr {
        match self {
            Variant::MlDsa44 => MLDSA44_CSTR,
            Variant::MlDsa65 => MLDSA65_CSTR,
            Variant::MlDsa87 => MLDSA87_CSTR,
        }
    }
}

pub struct PKeyMlDsaBuilder<'a, 'opb, T>
where
    'a: 'opb,
{
    bld: OsslParamBuilder<'opb>,
    variant: Variant,
    _m: PhantomData<&'a T>,
}

impl<'a, 'opb, T> PKeyMlDsaBuilder<'a, 'opb, T> {
    /// Creates a new `PKeyMlDsaBuilder` to build ML-DSA private or
    /// public keys.
    pub fn new(
        variant: Variant,
        public: &'opb [u8],
        private: Option<&'opb [u8]>,
    ) -> Result<PKeyMlDsaBuilder<'a, 'opb, T>, ErrorStack> {
        let mut bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public)?;
        if let Some(private) = private {
            bld.add_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, private)?
        };
        Ok(PKeyMlDsaBuilder::<'a, 'opb, T> {
            bld,
            variant,
            _m: PhantomData,
        })
    }

    /// Creates a new `PKeyMlDsaBuilder` to build ML-DSA private keys
    /// from a seed.
    pub fn from_seed(
        variant: Variant,
        seed: &'opb [u8],
    ) -> Result<PKeyMlDsaBuilder<'a, 'opb, T>, ErrorStack> {
        let mut bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_SEED, seed)?;
        Ok(PKeyMlDsaBuilder::<'a, 'opb, T> {
            bld,
            variant,
            _m: PhantomData,
        })
    }

    /// Build PKey. Internal.
    #[corresponds(EVP_PKEY_fromdata)]
    fn build_internal(&'a mut self, selection: c_int) -> Result<PKey<T>, ErrorStack> {
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

impl<'a, 'opb> PKeyMlDsaBuilder<'a, 'opb, Private> {
    /// Returns the Private ML-DSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(&'a mut self) -> Result<PKey<Private>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_KEYPAIR)
    }

    /// Creates a new `PKeyMlDsaBuilder` to generate a new ML-DSA key
    /// pair.
    pub fn new_generate(
        variant: Variant,
    ) -> Result<PKeyMlDsaBuilder<'a, 'opb, Private>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        Ok(PKeyMlDsaBuilder::<Private> {
            bld,
            variant,
            _m: PhantomData,
        })
    }

    /// Generate an ML-DSA PKey.
    pub fn generate(&'a mut self) -> Result<PKey<Private>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(None, self.variant.as_str(), None)?;
        ctx.keygen_init()?;
        let params = self.bld.to_param()?;
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_params(ctx.as_ptr(), params.as_ptr()))?;
        }
        ctx.generate()
    }
}

impl<'a, 'opb> PKeyMlDsaBuilder<'a, 'opb, Public> {
    /// Returns the Public ML-DSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(&'a mut self) -> Result<PKey<Public>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

pub struct PKeyMlDsaParams<T> {
    params: OsslParamArray,
    _m: PhantomData<T>,
}

impl<T> PKeyMlDsaParams<T> {
    /// Creates a new `PKeyMlDsaParams` from existing ML-DSA PKey. Internal.
    #[corresponds(EVP_PKEY_todata)]
    fn _new_from_pkey<S>(
        pkey: &PKey<S>,
        selection: c_int,
    ) -> Result<PKeyMlDsaParams<T>, ErrorStack> {
        unsafe {
            let mut params: *mut ffi::OSSL_PARAM = ptr::null_mut();
            cvt(ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params))?;
            Ok(PKeyMlDsaParams::<T> {
                params: OsslParamArray::from_ptr(params),
                _m: PhantomData,
            })
        }
    }
}

impl PKeyMlDsaParams<Public> {
    /// Creates a new `PKeyMlDsaParams` from existing Public ML-DSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey<S>(pkey: &PKey<S>) -> Result<PKeyMlDsaParams<Public>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PUBLIC_KEY)
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_PUB_KEY)
    }
}

impl PKeyMlDsaParams<Private> {
    /// Creates a new `PKeyMlDsaParams` from existing Private ML-DSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Private>) -> Result<PKeyMlDsaParams<Private>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_KEYPAIR)
    }

    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_SEED)
    }

    /// Returns the private key.
    pub fn private_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate_octet_string(OSSL_PKEY_PARAM_PRIV_KEY)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::signature::Signature;

    #[test]
    fn test_generate_ml_dsa_44() {
        test_generate(Variant::MlDsa44);
    }

    #[test]
    fn test_generate_ml_dsa_65() {
        test_generate(Variant::MlDsa65);
    }

    #[test]
    fn test_generate_ml_dsa_87() {
        test_generate(Variant::MlDsa87);
    }

    fn test_generate(variant: Variant) {
        let mut bld = PKeyMlDsaBuilder::<Private>::new_generate(variant).unwrap();
        let key = bld.generate().unwrap();

        let mut algo = Signature::for_ml_dsa(variant).unwrap();

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
        let public_params = PKeyMlDsaParams::<Public>::from_pkey(&key).unwrap();
        let key_pub =
            PKeyMlDsaBuilder::<Public>::new(variant, public_params.public_key().unwrap(), None)
                .unwrap()
                .build()
                .unwrap();
        let mut ctx = PkeyCtx::new(&key_pub).unwrap();
        let mut algo = Signature::for_ml_dsa(variant).unwrap();

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

        // Derive a new PKEY with the public and private bits.
        let private_params = PKeyMlDsaParams::<Private>::from_pkey(&key).unwrap();
        let key_priv = PKeyMlDsaBuilder::<Private>::new(
            variant,
            public_params.public_key().unwrap(),
            Some(private_params.private_key().unwrap()),
        )
        .unwrap()
        .build()
        .unwrap();

        // And redo the signature and verification.
        let mut signature = vec![];
        let mut ctx = PkeyCtx::new(&key_priv).unwrap();
        ctx.sign_message_init(&mut algo).unwrap();
        ctx.sign_to_vec(&data[..], &mut signature).unwrap();

        // Verify good version with the public PKEY.
        ctx.verify_message_init(&mut algo).unwrap();
        let valid = ctx.verify(&data[..], &signature);
        assert!(matches!(valid, Ok(true)));
        assert!(ErrorStack::get().errors().is_empty());

        // Derive a new PKEY from the private seed.
        let key_priv = PKeyMlDsaBuilder::<Private>::from_seed(
            variant,
            private_params.private_key_seed().unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();

        // And redo the signature and verification.
        let mut signature = vec![];
        let mut ctx = PkeyCtx::new(&key_priv).unwrap();
        ctx.sign_message_init(&mut algo).unwrap();
        ctx.sign_to_vec(&data[..], &mut signature).unwrap();

        // Verify good version with the public PKEY.
        ctx.verify_message_init(&mut algo).unwrap();
        let valid = ctx.verify(&data[..], &signature);
        assert!(matches!(valid, Ok(true)));
        assert!(ErrorStack::get().errors().is_empty());
    }
}
