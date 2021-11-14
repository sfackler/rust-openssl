//! The asymmetric encryption context.
//!
//! # Examples
//!
//! Encrypt data with RSA
//!
//! ```
//! use openssl::rsa::Rsa;
//! use openssl::pkey::PKey;
//! use openssl::pkey_ctx::PkeyCtx;
//!
//! let key = Rsa::generate(4096).unwrap();
//! let key = PKey::from_rsa(key).unwrap();
//!
//! let mut ctx = PkeyCtx::new(&key).unwrap();
//! ctx.encrypt_init().unwrap();
//!
//! let data = b"Some Crypto Text";
//! let mut ciphertext = vec![];
//! ctx.encrypt_to_vec(data, &mut ciphertext).unwrap();
//! ```
use crate::error::ErrorStack;
use crate::md::MdRef;
use crate::pkey::{HasPublic, PKeyRef};
use crate::rsa::Padding;
#[cfg(any(ossl102, libressl310))]
use crate::util;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
#[cfg(any(ossl102, libressl310))]
use libc::c_int;
#[cfg(any(ossl102, libressl310))]
use std::convert::TryFrom;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EVP_PKEY_CTX;
    fn drop = ffi::EVP_PKEY_CTX_free;

    pub struct PkeyCtx;
    /// A reference to a [`PkeyCtx`].
    pub struct PkeyCtxRef;
}

impl PkeyCtx {
    #[inline]
    pub fn new<T>(pkey: &PKeyRef<T>) -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut()))?;
            Ok(PkeyCtx::from_ptr(ptr))
        }
    }
}

impl PkeyCtxRef {
    /// Prepares the context for encryption using the public key.
    ///
    /// This corresponds to [`EVP_PKEY_encrypt_init`].
    ///
    /// [`EVP_PKEY_encrypt_init`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt_init.html
    #[inline]
    pub fn encrypt_init(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_encrypt_init(self.as_ptr()))?;
        }

        Ok(())
    }

    /// Prepares the context for encryption using the private key.
    ///
    /// This corresponds to [`EVP_PKEY_decrypt_init`].
    ///
    /// [`EVP_PKEY_decrypt_init`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt_init.html
    #[inline]
    pub fn decrypt_init(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_decrypt_init(self.as_ptr()))?;
        }

        Ok(())
    }

    /// Prepares the context for shared secret derivation.
    ///
    /// This corresponds to [`EVP_PKEY_derive_init`].
    ///
    /// [`EVP_PKEY_derive_init`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_derive_init.html
    #[inline]
    pub fn derive_init(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_derive_init(self.as_ptr()))?;
        }

        Ok(())
    }

    /// Returns the RSA padding mode in use.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_get_rsa_padding`].
    ///
    /// [`EVP_PKEY_CTX_get_rsa_padding`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_CTX_get_rsa_padding.html
    #[inline]
    pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
        let mut pad = 0;
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_get_rsa_padding(self.as_ptr(), &mut pad))?;
        }

        Ok(Padding::from_raw(pad))
    }

    /// Sets the RSA padding mode.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_padding`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_padding`]: https://www.openssl.org/docs/manmaster/crypto/EVP_PKEY_CTX_set_rsa_padding.html
    #[inline]
    pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_padding(
                self.as_ptr(),
                padding.as_raw(),
            ))?;
        }

        Ok(())
    }

    /// Sets the RSA MGF1 algorithm.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_mgf1_md`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_mgf1_md`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_CTX_set_rsa_mgf1_md.html
    #[inline]
    pub fn set_rsa_mgf1_md(&mut self, md: &MdRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(
                self.as_ptr(),
                md.as_ptr(),
            ))?;
        }

        Ok(())
    }

    /// Sets the RSA OAEP algorithm.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_oaep_md`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_oaep_md`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_CTX_set_rsa_oaep_md.html
    #[cfg(any(ossl102, libressl310))]
    #[inline]
    pub fn set_rsa_oaep_md(&mut self, md: &MdRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_oaep_md(
                self.as_ptr(),
                md.as_ptr() as *mut _,
            ))?;
        }

        Ok(())
    }

    /// Sets the RSA OAEP label.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set0_rsa_oaep_label`].
    ///
    /// [`EVP_PKEY_CTX_set0_rsa_oaep_label`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_CTX_set0_rsa_oaep_label.html
    #[cfg(any(ossl102, libressl310))]
    pub fn set_rsa_oaep_label(&mut self, label: &[u8]) -> Result<(), ErrorStack> {
        let len = c_int::try_from(label.len()).unwrap();

        unsafe {
            let p = util::crypto_malloc(label.len())?;
            ptr::copy_nonoverlapping(label.as_ptr(), p as *mut _, label.len());

            let r = cvt(ffi::EVP_PKEY_CTX_set0_rsa_oaep_label(self.as_ptr(), p, len));
            if r.is_err() {
                util::crypto_free(p);
            }
            r?;
        }

        Ok(())
    }

    /// Sets the peer key used for secret derivation.
    ///
    /// This corresponds to [`EVP_PKEY_derive_set_peer`].
    ///
    /// [`EVP_PKEY_derive_set_peer`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_derive_set_peer.html
    pub fn derive_set_peer<T>(&mut self, key: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPublic,
    {
        unsafe {
            cvt(ffi::EVP_PKEY_derive_set_peer(self.as_ptr(), key.as_ptr()))?;
        }

        Ok(())
    }

    /// Encrypts data using the public key.
    ///
    /// If `to` is set to `None`, an upper bound on the number of bytes required for the output buffer will be
    /// returned.
    ///
    /// This corresponds to [`EVP_PKEY_encrypt`].
    ///
    /// [`EVP_PKEY_encrypt`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt.html
    #[inline]
    pub fn encrypt(&mut self, from: &[u8], to: Option<&mut [u8]>) -> Result<usize, ErrorStack> {
        let mut written = to.as_ref().map_or(0, |b| b.len());
        unsafe {
            cvt(ffi::EVP_PKEY_encrypt(
                self.as_ptr(),
                to.map_or(ptr::null_mut(), |b| b.as_mut_ptr()),
                &mut written,
                from.as_ptr(),
                from.len(),
            ))?;
        }

        Ok(written)
    }

    /// Like [`Self::encrypt`] but appends ciphertext to a [`Vec`].
    pub fn encrypt_to_vec(&mut self, from: &[u8], out: &mut Vec<u8>) -> Result<usize, ErrorStack> {
        let base = out.len();
        let len = self.encrypt(from, None)?;
        out.resize(base + len, 0);
        let len = self.encrypt(from, Some(&mut out[base..]))?;
        out.truncate(base + len);
        Ok(len)
    }

    /// Decrypts data using the private key.
    ///
    /// If `to` is set to `None`, an upper bound on the number of bytes required for the output buffer will be
    /// returned.
    ///
    /// This corresponds to [`EVP_PKEY_decrypt`].
    ///
    /// [`EVP_PKEY_decrypt`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt.html
    #[inline]
    pub fn decrypt(&mut self, from: &[u8], to: Option<&mut [u8]>) -> Result<usize, ErrorStack> {
        let mut written = to.as_ref().map_or(0, |b| b.len());
        unsafe {
            cvt(ffi::EVP_PKEY_decrypt(
                self.as_ptr(),
                to.map_or(ptr::null_mut(), |b| b.as_mut_ptr()),
                &mut written,
                from.as_ptr(),
                from.len(),
            ))?;
        }

        Ok(written)
    }

    /// Like [`Self::decrypt`] but appends plaintext to a [`Vec`].
    pub fn decrypt_to_vec(&mut self, from: &[u8], out: &mut Vec<u8>) -> Result<usize, ErrorStack> {
        let base = out.len();
        let len = self.decrypt(from, None)?;
        out.resize(base + len, 0);
        let len = self.decrypt(from, Some(&mut out[base..]))?;
        out.truncate(base + len);
        Ok(len)
    }

    /// Derives a shared secrete between two keys.
    ///
    /// If `buf` is set to `None`, an upper bound on the number of bytes required for the buffer will be returned.
    ///
    /// This corresponds to [`EVP_PKEY_derive`].
    ///
    /// [`EVP_PKEY_derive`]: https://www.openssl.org/docs/manmaster/crypto/EVP_PKEY_derive_init.html
    pub fn derive(&mut self, buf: Option<&mut [u8]>) -> Result<usize, ErrorStack> {
        let mut len = buf.as_ref().map_or(0, |b| b.len());
        unsafe {
            cvt(ffi::EVP_PKEY_derive(
                self.as_ptr(),
                buf.map_or(ptr::null_mut(), |b| b.as_mut_ptr()),
                &mut len,
            ))?;
        }

        Ok(len)
    }

    /// Like [`Self::derive`] but appends the secret to a [`Vec`].
    pub fn derive_to_vec(&mut self, buf: &mut Vec<u8>) -> Result<usize, ErrorStack> {
        let base = buf.len();
        let len = self.derive(None)?;
        buf.resize(base + len, 0);
        let len = self.derive(Some(&mut buf[base..]))?;
        buf.truncate(base + len);
        Ok(len)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::dh::Dh;
    use crate::ec::{EcGroup, EcKey};
    use crate::md::Md;
    use crate::nid::Nid;
    use crate::pkey::PKey;
    use crate::rsa::Rsa;

    #[test]
    fn decrypt_without_private_key() {
        let key = Rsa::public_key_from_pem(include_bytes!("../test/rsa.pem.pub")).unwrap();
        let key = PKey::from_rsa(key).unwrap();

        let mut ctx = PkeyCtx::new(&key).unwrap();

        let pt = "hello".as_bytes();

        ctx.encrypt_init().unwrap();
        let mut ct = vec![];
        ctx.encrypt_to_vec(pt, &mut ct).unwrap();

        ctx.decrypt_init().unwrap();
        let mut out = vec![];
        ctx.decrypt_to_vec(&ct, &mut out).unwrap_err();
    }

    #[test]
    fn rsa() {
        let key = include_bytes!("../test/rsa.pem");
        let rsa = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut ctx = PkeyCtx::new(&pkey).unwrap();
        ctx.encrypt_init().unwrap();
        ctx.set_rsa_padding(Padding::PKCS1).unwrap();

        let pt = "hello world".as_bytes();
        let mut ct = vec![];
        ctx.encrypt_to_vec(pt, &mut ct).unwrap();

        ctx.decrypt_init().unwrap();
        ctx.set_rsa_padding(Padding::PKCS1).unwrap();

        let mut out = vec![];
        ctx.decrypt_to_vec(&ct, &mut out).unwrap();

        assert_eq!(pt, out);
    }

    #[test]
    #[cfg(any(ossl102, libressl310))]
    fn rsa_oaep() {
        let key = include_bytes!("../test/rsa.pem");
        let rsa = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut ctx = PkeyCtx::new(&pkey).unwrap();
        ctx.encrypt_init().unwrap();
        ctx.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        ctx.set_rsa_oaep_md(Md::sha256()).unwrap();
        ctx.set_rsa_mgf1_md(Md::sha256()).unwrap();

        let pt = "hello world".as_bytes();
        let mut ct = vec![];
        ctx.encrypt_to_vec(pt, &mut ct).unwrap();

        ctx.decrypt_init().unwrap();
        ctx.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        ctx.set_rsa_oaep_md(Md::sha256()).unwrap();
        ctx.set_rsa_mgf1_md(Md::sha256()).unwrap();

        let mut out = vec![];
        ctx.decrypt_to_vec(&ct, &mut out).unwrap();

        assert_eq!(pt, out);
    }

    #[test]
    fn dh_derive_without_components() {
        let key1 = Dh::params_from_pem(include_bytes!("../test/dhparams.pem")).unwrap();
        let key1 = PKey::from_dh(key1).unwrap();
        let key2 = Dh::params_from_pem(include_bytes!("../test/dhparams.pem"))
            .unwrap()
            .generate_key()
            .unwrap();
        let key2 = PKey::from_dh(key2).unwrap();

        let mut ctx = PkeyCtx::new(&key1).unwrap();
        ctx.derive_init().unwrap();
        ctx.derive_set_peer(&key2).unwrap();

        let mut buf = vec![];
        ctx.derive_to_vec(&mut buf).unwrap_err();
    }

    #[test]
    fn derive() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key1 = EcKey::generate(&group).unwrap();
        let key1 = PKey::from_ec_key(key1).unwrap();
        let key2 = EcKey::generate(&group).unwrap();
        let key2 = PKey::from_ec_key(key2).unwrap();

        let mut ctx = PkeyCtx::new(&key1).unwrap();
        ctx.derive_init().unwrap();
        ctx.derive_set_peer(&key2).unwrap();

        let mut buf = vec![];
        ctx.derive_to_vec(&mut buf).unwrap();
    }
}
