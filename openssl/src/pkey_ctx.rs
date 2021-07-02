//! PKeyContext operations
use crate::error::ErrorStack;
#[cfg(ossl110)]
use crate::hash::MessageDigest;
use crate::pkey::{HasPrivate, HasPublic, Id, PKeyRef};
use crate::{cvt, cvt_p};
use foreign_types::ForeignTypeRef;
use std::marker::PhantomData;
#[cfg(ossl110)]
use std::os::raw::{c_int, c_uchar};
use std::ptr;

/// HKDF modes of operation. See [`hkdf_mode`](PKeyContext::set_hkdf_mode)
#[cfg(ossl111)]
pub struct HkdfMode(c_int);

impl HkdfMode {
    /// Extract followed by expand
    pub const EXTRACT_THEN_EXPAND: HkdfMode = HkdfMode(ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);
    /// Extract only HKDF
    pub const EXTRACT: HkdfMode = HkdfMode(ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    /// Expand only HKDF
    pub const EXPAND: HkdfMode = HkdfMode(ffi::EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
}

/// A type used for performing operations with PKeys
pub struct PKeyContext<'a>(*mut ffi::EVP_PKEY_CTX, PhantomData<&'a ()>);

unsafe impl<'a> Sync for PKeyContext<'a> {}
unsafe impl<'a> Send for PKeyContext<'a> {}

#[allow(clippy::len_without_is_empty)]
impl<'a> PKeyContext<'a> {
    /// Creates a new `PKeyContext` using the provided private key.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_new`].
    ///
    /// [`EVP_PKEY_CTX_new`]: https://www.openssl.org/docs/man1.0.2/crypto/EVP_PKEY_CTX_new.html
    pub fn new<T>(key: &'a PKeyRef<T>) -> Result<PKeyContext<'a>, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            cvt_p(ffi::EVP_PKEY_CTX_new(key.as_ptr(), ptr::null_mut()))
                .map(|p| PKeyContext(p, PhantomData))
        }
    }

    /// Initialize the PkeyContext for key derivation operations
    ///
    /// This corresponds to [`EVP_PKEY_derive_init`].
    ///
    /// [`EVP_PKEY_derive_init`]: https://www.openssl.org/docs/man1.0.2/crypto/EVP_PKEY_derive_init.html
    pub fn derive_init(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::EVP_PKEY_derive_init(self.0)).map(|_| ()) }
    }

    /// Sets the peer key used for secret derivation.
    ///
    /// This corresponds to [`EVP_PKEY_derive_set_peer`]:
    ///
    /// [`EVP_PKEY_derive_set_peer`]: https://www.openssl.org/docs/man1.0.2/crypto/EVP_PKEY_derive_init.html
    pub fn set_peer<T>(&mut self, key: &'a PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPublic,
    {
        unsafe { cvt(ffi::EVP_PKEY_derive_set_peer(self.0, key.as_ptr())).map(|_| ()) }
    }

    /// Creates a new `PKeyContext` using the algorithm specified by `id`.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_new_id`]
    ///
    /// [`EVP_PKEY_CTX_new_id`]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_new_id.html
    #[cfg(ossl110)]
    pub fn new_id(id: Id) -> Result<Self, ErrorStack> {
        unsafe {
            cvt_p(ffi::EVP_PKEY_CTX_new_id(id.as_raw(), ptr::null_mut()))
                .map(|p| PKeyContext(p, PhantomData))
        }
    }

    /// Sets the digest to use for HKDF derivation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_hkdf_md`].
    ///
    /// # Warning
    /// This function will result in an error unless the `PKeyContext` was created with
    /// [`new_id`](PKeyContext::new_id) specifying the `HKDF` Id.
    ///
    /// [`EVP_PKEY_CTX_set_hkdf_md`]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_set_hkdf_md.html
    #[cfg(ossl110)]
    pub fn set_hkdf_md(&mut self, digest: MessageDigest) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_hkdf_md(self.0, digest.as_ptr()))?;
        }

        Ok(())
    }

    /// Sets the HKDF mode of operation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_hkdf_mode`]
    ///
    /// # Warning
    /// This function will result in an error unless the context was created with
    /// [new_id](PKeyContext::new_id) specifying the `HKDF` Id.
    ///
    /// [`EVP_PKEY_CTX_hkdf_mode`]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_hkdf_mode.html
    #[cfg(ossl111)]
    pub fn set_hkdf_mode(&mut self, mode: HkdfMode) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_hkdf_mode(self.0, mode.0))?;
        }

        Ok(())
    }

    /// Sets the input keying material for HKDF derivation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set1_hkdf_key`].
    ///
    /// [`EVP_PKEY_CTX_set1_hkdf_key`]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_set1_hkdf_key.html
    #[cfg(ossl110)]
    pub fn set_hkdf_key(&mut self, key: &[u8]) -> Result<(), ErrorStack> {
        let len = key.len();
        assert!(len <= std::i32::MAX as usize);

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_key(
                self.0,
                key.as_ptr() as *mut c_uchar,
                len as c_int,
            ))?;

            Ok(())
        }
    }

    /// Sets the salt value for HKDF derivation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set1_hkdf_salt`].
    ///
    /// [`EVP_PKEY_CTX_set1_hkdf_salt`]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_set1_hkdf_salt.html
    #[cfg(ossl110)]
    pub fn set_hkdf_salt(&mut self, salt: &[u8]) -> Result<(), ErrorStack> {
        let len = salt.len();
        assert!(len <= std::i32::MAX as usize);

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_salt(
                self.0,
                salt.as_ptr() as *mut c_uchar,
                len as c_int,
            ))?;

            Ok(())
        }
    }

    /// Appends info bytes for HKDF derivation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_add1_hkdf_info`].
    ///
    /// # Warning
    ///
    /// On OpenSSL versions < 3.0, total length of the `info` buffer must not exceed 1024 bytes
    /// in length
    ///
    /// [`EVP_PKEY_CTX_add1_hkdf_info`]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_add1_hkdf_info.html
    #[cfg(ossl110)]
    pub fn add_hkdf_info(&mut self, info: &[u8]) -> Result<(), ErrorStack> {
        let len = info.len();
        assert!(len <= std::i32::MAX as usize);

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_add1_hkdf_info(
                self.0,
                info.as_ptr() as *mut c_uchar,
                len as c_int,
            ))?;

            Ok(())
        }
    }

    /// Returns the size of the derivation output.
    ///
    /// It can be used to size the buffer passed to [`PKeyContext::derive`].
    ///
    /// This corresponds to [`EVP_PKEY_derive`].
    ///
    /// # Warning
    ///
    /// When using this `PKeyContext` for HKDF, this function is only allowed when using HKDF with
    /// [`EXTRACT`](HkdfMode::EXTRACT) mode.
    ///
    /// [`PKeyContext::derive`]: #method.derive
    /// [`EVP_PKEY_derive`]: https://www.openssl.org/docs/man1.0.2/crypto/EVP_PKEY_derive_init.html
    pub fn derive_len(&mut self) -> Result<usize, ErrorStack> {
        unsafe {
            let mut len = 0;
            cvt(ffi::EVP_PKEY_derive(self.0, ptr::null_mut(), &mut len)).map(|_| len)
        }
    }

    /// Derive the configured output based on algorithm
    ///
    /// This corresponds to [`EVP_PKEY_derive`]
    ///
    /// [`EVP_PKEY_derive`]: https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_derive.html
    pub fn derive(&mut self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut len = buf.len();
            cvt(ffi::EVP_PKEY_derive(self.0, buf.as_mut_ptr(), &mut len))?;
            Ok(len)
        }
    }

    /// A convenience function which derives a shared secret and returns it in a new buffer.
    ///
    /// This simply wraps [`PKeyContext::len`] and [`PKeyContext::derive`].
    ///
    /// # Warning
    ///
    /// When using this `PKeyContext` for HKDF, this function is only allowed when using HKDF with
    /// [`EXTRACT`](HkdfMode::EXTRACT) mode.
    /// [`PKeyContext::len`]: #method.len
    /// [`PKeyContext::derive`]: #method.derive
    pub fn derive_to_vec(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let len = self.derive_len()?;
        let mut buf = vec![0; len];
        let len = self.derive(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}

impl<'a> Drop for PKeyContext<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_PKEY_CTX_free(self.0);
        }
    }
}

/// One-shot HKDF expand, filling the buffer
#[cfg(ossl111)]
pub fn hkdf_expand(
    digest: MessageDigest,
    key: &[u8],
    info: &[u8],
    buf: &mut [u8],
) -> Result<(), ErrorStack> {
    let mut ctx = PKeyContext::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(digest)?;
    ctx.set_hkdf_mode(HkdfMode::EXPAND)?;
    ctx.set_hkdf_key(key)?;
    ctx.add_hkdf_info(info)?;
    ctx.derive(buf)?;

    Ok(())
}

/// One-shot HKDF extract
#[cfg(ossl111)]
pub fn hkdf_extract(digest: MessageDigest, key: &[u8], salt: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut ctx = PKeyContext::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(digest)?;
    ctx.set_hkdf_mode(HkdfMode::EXTRACT)?;
    ctx.set_hkdf_key(key)?;
    ctx.set_hkdf_salt(salt)?;

    let mut buf = vec![0u8; ctx.derive_len()?];
    ctx.derive(&mut buf)?;
    Ok(buf)
}

/// One-shot HKDF extract-and-expand, filling the buffer
#[cfg(ossl110)]
pub fn hkdf(
    digest: MessageDigest,
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    buf: &mut [u8],
) -> Result<(), ErrorStack> {
    let mut ctx = PKeyContext::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(digest)?;
    ctx.set_hkdf_key(key)?;
    ctx.set_hkdf_salt(salt)?;
    ctx.add_hkdf_info(info)?;
    ctx.derive(buf)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ec::{EcGroup, EcKey};
    use crate::nid::Nid;
    use crate::pkey::PKey;
    #[cfg(ossl110)]
    use hex::{self, FromHex};

    // ECDH DERIVE TESTS
    #[test]
    fn derive_without_peer() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let mut ctx = PKeyContext::new(&pkey).unwrap();
        ctx.derive_init().unwrap();
        ctx.derive_to_vec().unwrap_err();
    }

    #[test]
    fn test_ec_key_derive() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let ec_key2 = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let pkey2 = PKey::from_ec_key(ec_key2).unwrap();
        let mut ctx = PKeyContext::new(&pkey).unwrap();
        ctx.derive_init().unwrap();
        ctx.set_peer(&pkey2).unwrap();
        let shared = ctx.derive_to_vec().unwrap();
        assert!(!shared.is_empty());
    }

    // HKDF DERIVE TESTS
    #[cfg(ossl110)]
    const IKM: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    #[cfg(ossl110)]
    const SALT: &str = "000102030405060708090a0b0c";
    #[cfg(ossl110)]
    const INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
    #[cfg(ossl110)]
    const L: usize = 42;

    #[cfg(ossl111)]
    const PRK: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

    #[cfg(ossl110)]
    const OKM: &str = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                       34007208d5b887185865";

    #[cfg(ossl111)]
    #[test]
    fn test_hkdf_expand() {
        let ikm = Vec::from_hex(PRK).unwrap();
        let info = Vec::from_hex(INFO).unwrap();
        let mut out = vec![0u8; L];

        hkdf_expand(MessageDigest::sha256(), &ikm, &info, &mut out).unwrap();
        assert_eq!(out, Vec::from_hex(OKM).unwrap());
    }

    #[cfg(ossl111)]
    #[test]
    fn test_hkdf_extract() {
        let ikm = Vec::from_hex(IKM).unwrap();
        let salt = Vec::from_hex(SALT).unwrap();
        let out = hkdf_extract(MessageDigest::sha256(), &ikm, &salt).unwrap();
        assert_eq!(out, Vec::from_hex(PRK).unwrap());
    }

    #[cfg(ossl110)]
    #[test]
    fn test_hkdf() {
        let ikm = Vec::from_hex(IKM).unwrap();
        let salt = Vec::from_hex(SALT).unwrap();
        let info = Vec::from_hex(INFO).unwrap();
        let mut out = vec![0u8; L];

        hkdf(MessageDigest::sha256(), &ikm, &salt, &info, &mut out).unwrap();
        assert_eq!(out, Vec::from_hex(OKM).unwrap());
    }

    #[cfg(ossl110)]
    #[cfg(not(ossl300))]
    #[test]
    fn test_large_hkdf_info() {
        let too_big = vec![0u8; 1025];
        let mut hkdf = PKeyContext::new_id(Id::HKDF).unwrap();
        hkdf.derive_init().unwrap();
        hkdf.set_hkdf_md(MessageDigest::sha256()).unwrap();
        assert!(hkdf.add_hkdf_info(&too_big).is_err());
    }
}
