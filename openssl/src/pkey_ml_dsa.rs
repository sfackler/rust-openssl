//! Module-Lattice-Based Digital Signatures.
//!
//! ML-DSA is a signature algorithm that is believed to be secure
//! against adversaries with quantum computers.  It has been
//! standardized by NIST as [FIPS 204].
//!
//! [FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final

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
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Variant {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Variant::MlDsa44 => "ML-DSA-44",
            Variant::MlDsa65 => "ML-DSA-65",
            Variant::MlDsa87 => "ML-DSA-87",
        }
    }

    pub(crate) fn as_cstr(&self) -> &'static CStr {
        match self {
            Variant::MlDsa44 => CStr::from_bytes_with_nul(b"ML-DSA-44\0"),
            Variant::MlDsa65 => CStr::from_bytes_with_nul(b"ML-DSA-65\0"),
            Variant::MlDsa87 => CStr::from_bytes_with_nul(b"ML-DSA-87\0"),
        }.unwrap()
    }
}

pub struct PKeyMlDsaBuilder<T> {
    bld: OsslParamBuilder,
    variant: Variant,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyMlDsaBuilder<T> {
    /// Creates a new `PKeyMlDsaBuilder` to build ML-DSA private or
    /// public keys.
    pub fn new(
        variant: Variant,
        public: &[u8],
        private: Option<&[u8]>,
    ) -> Result<PKeyMlDsaBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public)?;
        if let Some(private) = private {
            bld.add_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, private)?
        };
        Ok(PKeyMlDsaBuilder::<T> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Creates a new `PKeyMlDsaBuilder` to build ML-DSA private keys
    /// from a seed.
    pub fn from_seed(
        variant: Variant,
        seed: &[u8],
    ) -> Result<PKeyMlDsaBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_SEED, seed)?;
        Ok(PKeyMlDsaBuilder::<T> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Build PKey. Internal.
    #[corresponds(EVP_PKEY_fromdata)]
    fn build_internal(self, selection: c_int)
                      -> Result<PKey<T>, ErrorStack>
    {
        let mut ctx = PkeyCtx::new_from_name(
            None, self.variant.as_str(), None)?;
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

impl PKeyMlDsaBuilder<Private> {
    /// Returns the Private ML-DSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Private>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_KEYPAIR)
    }

    /// Creates a new `PKeyRsaBuilder` to generate a new ML-DSA key
    /// pair.
    pub fn new_generate(variant: Variant)
                        -> Result<PKeyMlDsaBuilder<Private>, ErrorStack>
    {
        let bld = OsslParamBuilder::new()?;
        Ok(PKeyMlDsaBuilder::<Private> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Generate an ML-DSA PKey.
    pub fn generate(self) -> Result<PKey<Private>, ErrorStack> {
        let mut ctx = PkeyCtx::new_from_name(
            None, self.variant.as_str(), None)?;
        ctx.keygen_init()?;
        let params = self.bld.to_param()?;
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_params(ctx.as_ptr(), params.as_ptr()))?;
        }
        ctx.generate()
    }
}

impl PKeyMlDsaBuilder<Public> {
    /// Returns the Public ML-DSA PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Public>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

pub struct PKeyMlDsaParams<T> {
    params: OsslParam,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyMlDsaParams<T> {
    /// Creates a new `PKeyMlDsaParams` from existing ECDSA PKey. Internal.
    #[corresponds(EVP_PKEY_todata)]
    fn _new_from_pkey<S>(pkey: &PKey<S>, selection: c_int)
                         -> Result<PKeyMlDsaParams<T>, ErrorStack>
    {
        unsafe {
            let mut params: *mut ffi::OSSL_PARAM = ptr::null_mut();
            cvt(ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params))?;
            Ok(PKeyMlDsaParams::<T> {
                params: OsslParam::from_ptr(params),
                _m: ::std::marker::PhantomData,
            })
        }
    }
}

impl PKeyMlDsaParams<Public> {
    /// Creates a new `PKeyMlDsaParams` from existing Public ECDSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey<S>(pkey: &PKey<S>) -> Result<PKeyMlDsaParams<Public>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PUBLIC_KEY)
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> Result<&[u8], ErrorStack> {
        self.params
            .locate(OSSL_PKEY_PARAM_PUB_KEY).unwrap()
            .get_octet_string()
    }
}

impl PKeyMlDsaParams<Private> {
    /// Creates a new `PKeyMlDsaParams` from existing Private ECDSA PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Private>) -> Result<PKeyMlDsaParams<Private>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_KEYPAIR)
    }

    /// Returns the private key seed.
    pub fn private_key_seed(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_SEED)?.get_octet_string()
    }

    /// Returns the private key.
    pub fn private_key(&self) -> Result<&[u8], ErrorStack> {
        self.params.locate(OSSL_PKEY_PARAM_PRIV_KEY)?.get_octet_string()
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
        let bld = PKeyMlDsaBuilder::<Private>::new_generate(variant).unwrap();
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
        let public_params =
            PKeyMlDsaParams::<Public>::from_pkey(&key).unwrap();
        let key_pub = PKeyMlDsaBuilder::<Public>::new(
            variant, public_params.public_key().unwrap(), None).unwrap()
            .build().unwrap();
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
    }
}
