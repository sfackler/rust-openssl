//! Envelope encryption.
//!
//! # Example
//!
//! ```rust
//! use openssl::rsa::Rsa;
//! use openssl::envelope::Seal;
//! use openssl::pkey::PKey;
//! use openssl::symm::Cipher;
//!
//! let rsa = Rsa::generate(2048).unwrap();
//! let key = PKey::from_rsa(rsa).unwrap();
//!
//! let cipher = Cipher::aes_256_cbc();
//! let mut seal = Seal::new(cipher, &[key]).unwrap();
//!
//! let secret = b"My secret message";
//! let mut encrypted = vec![0; secret.len() + cipher.block_size()];
//!
//! let mut enc_len = seal.update(secret, &mut encrypted).unwrap();
//! enc_len += seal.finalize(&mut encrypted[enc_len..]).unwrap();
//! encrypted.truncate(enc_len);
//! ```
use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, HasPublic, PKey, PKeyRef};
use crate::symm::Cipher;
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::cmp;
use std::ptr;

/// Represents an EVP_Seal context.
pub struct Seal {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    block_size: usize,
    iv: Option<Vec<u8>>,
    enc_keys: Vec<Vec<u8>>,
}

impl Seal {
    /// Creates a new `Seal`.
    pub fn new<T>(cipher: Cipher, pub_keys: &[PKey<T>]) -> Result<Seal, ErrorStack>
    where
        T: HasPublic,
    {
        unsafe {
            assert!(pub_keys.len() <= c_int::max_value() as usize);

            let ctx = cvt_p(ffi::EVP_CIPHER_CTX_new())?;
            let mut enc_key_ptrs = vec![];
            let mut pub_key_ptrs = vec![];
            let mut enc_keys = vec![];
            for key in pub_keys {
                let mut enc_key = vec![0; key.size()];
                let enc_key_ptr = enc_key.as_mut_ptr();
                enc_keys.push(enc_key);
                enc_key_ptrs.push(enc_key_ptr);
                pub_key_ptrs.push(key.as_ptr());
            }
            let mut iv = cipher.iv_len().map(|len| vec![0; len]);
            let iv_ptr = iv.as_mut().map_or(ptr::null_mut(), |v| v.as_mut_ptr());
            let mut enc_key_lens = vec![0; enc_keys.len()];

            cvt(ffi::EVP_SealInit(
                ctx,
                cipher.as_ptr(),
                enc_key_ptrs.as_mut_ptr(),
                enc_key_lens.as_mut_ptr(),
                iv_ptr,
                pub_key_ptrs.as_mut_ptr(),
                pub_key_ptrs.len() as c_int,
            ))?;

            for (buf, len) in enc_keys.iter_mut().zip(&enc_key_lens) {
                buf.truncate(*len as usize);
            }

            Ok(Seal {
                ctx,
                block_size: cipher.block_size(),
                iv,
                enc_keys,
            })
        }
    }

    /// Returns the initialization vector, if the cipher uses one.
    #[allow(clippy::option_as_ref_deref)]
    pub fn iv(&self) -> Option<&[u8]> {
        self.iv.as_ref().map(|v| &**v)
    }

    /// Returns the encrypted keys.
    pub fn encrypted_keys(&self) -> &[Vec<u8>] {
        &self.enc_keys
    }

    /// Feeds data from `input` through the cipher, writing encrypted bytes into `output`.
    ///
    /// The number of bytes written to `output` is returned. Note that this may
    /// not be equal to the length of `input`.
    ///
    /// # Panics
    ///
    /// Panics if `output.len() < input.len() + block_size` where `block_size` is
    /// the block size of the cipher (see `Cipher::block_size`), or if
    /// `output.len() > c_int::max_value()`.
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            assert!(output.len() >= input.len() + self.block_size);
            assert!(output.len() <= c_int::max_value() as usize);
            let mut outl = output.len() as c_int;
            let inl = input.len() as c_int;
            cvt(ffi::EVP_EncryptUpdate(
                self.ctx,
                output.as_mut_ptr(),
                &mut outl,
                input.as_ptr(),
                inl,
            ))?;
            Ok(outl as usize)
        }
    }

    /// Finishes the encryption process, writing any remaining data to `output`.
    ///
    /// The number of bytes written to `output` is returned.
    ///
    /// `update` should not be called after this method.
    ///
    /// # Panics
    ///
    /// Panics if `output` is less than the cipher's block size.
    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            assert!(output.len() >= self.block_size);
            let mut outl = cmp::min(output.len(), c_int::max_value() as usize) as c_int;

            cvt(ffi::EVP_SealFinal(self.ctx, output.as_mut_ptr(), &mut outl))?;

            Ok(outl as usize)
        }
    }
}

impl Drop for Seal {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_CIPHER_CTX_free(self.ctx);
        }
    }
}

/// Represents an EVP_Open context.
pub struct Open {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    block_size: usize,
}

impl Open {
    /// Creates a new `Open`.
    pub fn new<T>(
        cipher: Cipher,
        priv_key: &PKeyRef<T>,
        iv: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Open, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            assert!(encrypted_key.len() <= c_int::max_value() as usize);
            match (cipher.iv_len(), iv) {
                (Some(len), Some(iv)) => assert_eq!(len, iv.len(), "IV length mismatch"),
                (None, None) => {}
                (Some(_), None) => panic!("an IV was required but not provided"),
                (None, Some(_)) => panic!("an IV was provided but not required"),
            }

            let ctx = cvt_p(ffi::EVP_CIPHER_CTX_new())?;
            cvt(ffi::EVP_OpenInit(
                ctx,
                cipher.as_ptr(),
                encrypted_key.as_ptr(),
                encrypted_key.len() as c_int,
                iv.map_or(ptr::null(), |v| v.as_ptr()),
                priv_key.as_ptr(),
            ))?;
            Ok(Open {
                ctx,
                block_size: cipher.block_size(),
            })
        }
    }

    /// Feeds data from `input` through the cipher, writing decrypted bytes into `output`.
    ///
    /// The number of bytes written to `output` is returned. Note that this may
    /// not be equal to the length of `input`.
    ///
    /// # Panics
    ///
    /// Panics if `output.len() < input.len() + block_size` where
    /// `block_size` is the block size of the cipher (see `Cipher::block_size`),
    /// or if `output.len() > c_int::max_value()`.
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            assert!(output.len() >= input.len() + self.block_size);
            assert!(output.len() <= c_int::max_value() as usize);
            let mut outl = output.len() as c_int;
            let inl = input.len() as c_int;
            cvt(ffi::EVP_DecryptUpdate(
                self.ctx,
                output.as_mut_ptr(),
                &mut outl,
                input.as_ptr(),
                inl,
            ))?;
            Ok(outl as usize)
        }
    }

    /// Finishes the decryption process, writing any remaining data to `output`.
    ///
    /// The number of bytes written to `output` is returned.
    ///
    /// `update` should not be called after this method.
    ///
    /// # Panics
    ///
    /// Panics if `output` is less than the cipher's block size.
    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            assert!(output.len() >= self.block_size);
            let mut outl = cmp::min(output.len(), c_int::max_value() as usize) as c_int;

            cvt(ffi::EVP_OpenFinal(self.ctx, output.as_mut_ptr(), &mut outl))?;

            Ok(outl as usize)
        }
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_CIPHER_CTX_free(self.ctx);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pkey::PKey;
    use crate::symm::Cipher;

    #[test]
    fn public_encrypt_private_decrypt() {
        let private_pem = include_bytes!("../test/rsa.pem");
        let public_pem = include_bytes!("../test/rsa.pem.pub");
        let private_key = PKey::private_key_from_pem(private_pem).unwrap();
        let public_key = PKey::public_key_from_pem(public_pem).unwrap();
        let cipher = Cipher::aes_256_cbc();
        let secret = b"My secret message";

        let mut seal = Seal::new(cipher, &[public_key]).unwrap();
        let mut encrypted = vec![0; secret.len() + cipher.block_size()];
        let mut enc_len = seal.update(secret, &mut encrypted).unwrap();
        enc_len += seal.finalize(&mut encrypted[enc_len..]).unwrap();
        let iv = seal.iv();
        let encrypted_key = &seal.encrypted_keys()[0];

        let mut open = Open::new(cipher, &private_key, iv, encrypted_key).unwrap();
        let mut decrypted = vec![0; enc_len + cipher.block_size()];
        let mut dec_len = open.update(&encrypted[..enc_len], &mut decrypted).unwrap();
        dec_len += open.finalize(&mut decrypted[dec_len..]).unwrap();

        assert_eq!(&secret[..], &decrypted[..dec_len]);
    }
}
