//! Module-Lattice-Based Key-Encapsulation Mechanism.
//!
//! ML-KEM is a Key-Encapsulation Mechanism that is believed to be
//! secure against adversaries with quantum computers.  It has been
//! standardized by NIST as [FIPS 203].
//!
//! [FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final

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
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Variant {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Variant::MlKem512 => "ML-KEM-512",
            Variant::MlKem768 => "ML-KEM-768",
            Variant::MlKem1024 => "ML-KEM-1024",
        }
    }
}

pub struct PKeyMlKemBuilder<T> {
    bld: OsslParamBuilder,
    variant: Variant,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyMlKemBuilder<T> {
    /// Creates a new `PKeyMlKemBuilder` to build ML-KEM private or
    /// public keys.
    pub fn new(
        variant: Variant,
        public: &[u8],
        private: Option<&[u8]>,
    ) -> Result<PKeyMlKemBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public)?;
        if let Some(private) = private {
            bld.add_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, private)?
        };
        Ok(PKeyMlKemBuilder::<T> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Creates a new `PKeyMlKemBuilder` to build ML-KEM private keys
    /// from a seed.
    pub fn from_seed(variant: Variant, seed: &[u8]) -> Result<PKeyMlKemBuilder<T>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        bld.add_octet_string(OSSL_PKEY_PARAM_SEED, seed)?;
        Ok(PKeyMlKemBuilder::<T> {
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

impl PKeyMlKemBuilder<Private> {
    /// Returns the Private ML-KEM PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Private>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_KEYPAIR)
    }

    /// Creates a new `PKeyMlKemBuilder` to generate a new ML-KEM key
    /// pair.
    pub fn new_generate(variant: Variant) -> Result<PKeyMlKemBuilder<Private>, ErrorStack> {
        let bld = OsslParamBuilder::new()?;
        Ok(PKeyMlKemBuilder::<Private> {
            bld,
            variant,
            _m: ::std::marker::PhantomData,
        })
    }

    /// Generate an ML-KEM PKey.
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

impl PKeyMlKemBuilder<Public> {
    /// Returns the Public ML-KEM PKey from the provided parameters.
    #[corresponds(EVP_PKEY_fromdata)]
    pub fn build(self) -> Result<PKey<Public>, ErrorStack> {
        self.build_internal(ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

pub struct PKeyMlKemParams<T> {
    params: OsslParam,
    _m: ::std::marker::PhantomData<T>,
}

impl<T> PKeyMlKemParams<T> {
    /// Creates a new `PKeyMlKemParams` from existing ML-KEM PKey. Internal.
    #[corresponds(EVP_PKEY_todata)]
    fn _new_from_pkey<S>(
        pkey: &PKey<S>,
        selection: c_int,
    ) -> Result<PKeyMlKemParams<T>, ErrorStack> {
        unsafe {
            let mut params: *mut ffi::OSSL_PARAM = ptr::null_mut();
            cvt(ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params))?;
            Ok(PKeyMlKemParams::<T> {
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
}

impl PKeyMlKemParams<Public> {
    /// Creates a new `PKeyMlKemParams` from existing Public ML-KEM PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey<S>(pkey: &PKey<S>) -> Result<PKeyMlKemParams<Public>, ErrorStack> {
        Self::_new_from_pkey(pkey, ffi::EVP_PKEY_PUBLIC_KEY)
    }
}

impl PKeyMlKemParams<Private> {
    /// Creates a new `PKeyMlKemParams` from existing Private ML-KEM PKey.
    #[corresponds(EVP_PKEY_todata)]
    pub fn from_pkey(pkey: &PKey<Private>) -> Result<PKeyMlKemParams<Private>, ErrorStack> {
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

    #[test]
    fn test_generate_ml_kem_512() {
        test_generate(Variant::MlKem512);
    }

    #[test]
    fn test_generate_ml_kem_768() {
        test_generate(Variant::MlKem768);
    }

    #[test]
    fn test_generate_ml_kem_1024() {
        test_generate(Variant::MlKem1024);
    }

    fn test_generate(variant: Variant) {
        let bld = PKeyMlKemBuilder::<Private>::new_generate(variant).unwrap();
        let key = bld.generate().unwrap();

        // Encapsulate with the original PKEY.
        let (mut wrappedkey, mut genkey0) = (vec![], vec![]);
        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.encapsulate_init().unwrap();
        ctx.encapsulate_to_vec(&mut wrappedkey, &mut genkey0)
            .unwrap();

        let mut genkey1 = vec![];
        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.decapsulate_init().unwrap();
        ctx.decapsulate_to_vec(&wrappedkey, &mut genkey1).unwrap();

        assert_eq!(genkey0, genkey1);

        // Encapsulate with a PKEY derived from the public parameters.
        let public_params = PKeyMlKemParams::<Public>::from_pkey(&key).unwrap();
        let key_pub =
            PKeyMlKemBuilder::<Public>::new(variant, public_params.public_key().unwrap(), None)
                .unwrap()
                .build()
                .unwrap();

        let (mut wrappedkey, mut genkey0) = (vec![], vec![]);
        let mut ctx = PkeyCtx::new(&key_pub).unwrap();
        ctx.encapsulate_init().unwrap();
        ctx.encapsulate_to_vec(&mut wrappedkey, &mut genkey0)
            .unwrap();

        let mut genkey1 = vec![];
        let mut ctx = PkeyCtx::new(&key).unwrap();
        ctx.decapsulate_init().unwrap();
        ctx.decapsulate_to_vec(&wrappedkey, &mut genkey1).unwrap();

        assert_eq!(genkey0, genkey1);

        // Note that we can get the public parameter from the
        // PKeyMlKemParams::<Private> as well.  The same is not true
        // for ML-DSA, for example.
        let private_params = PKeyMlKemParams::<Private>::from_pkey(&key).unwrap();
        assert_eq!(
            public_params.public_key().unwrap(),
            private_params.public_key().unwrap()
        );
    }
}
