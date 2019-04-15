//! EVP provides a high-level interface to cryptographic functions.
//!
//! EvpSeal and EvpOpen provide public key encryption and decryption to implement digital "envelopes".
//!
//!
//! # Example
//!
//! Use aes_256_cbc to create new seal from public key and use it to encrypt data.
//!
//! ```rust
//!
//! extern crate openssl;
//!
//! use openssl::rsa::Rsa;
//! use openssl::evp::{EvpSeal};
//! use openssl::pkey::PKey;
//! use openssl::symm::Cipher;
//!
//! fn main() {
//!     let rsa = Rsa::generate(2048).unwrap();
//!     let pub_rsa =
//!         Rsa::from_public_components(rsa.n().to_owned().unwrap(), rsa.e().to_owned().unwrap())
//!             .unwrap();
//!     let public_key = PKey::from_rsa(pub_rsa).unwrap();
//!     let cipher = Cipher::aes_256_cbc();
//!     let mut seal = EvpSeal::new(cipher, vec![public_key]).unwrap();
//!     let secret = b"My secret message";
//!     let mut encrypted = vec![0; secret.len() + seal.bs()];
//!     let mut enc_len = seal.update(secret, &mut encrypted).unwrap();
//!     enc_len += seal.finalize(&mut encrypted[enc_len..]).unwrap();
//! }
//! ```
use error::ErrorStack;
use ffi;
use foreign_types::ForeignType;
use libc::{c_int, c_uchar};
use pkey::{PKey, Private, Public};
use std::cmp;
use symm::Cipher;
use {cvt, cvt_p};

/// Represents a EVP_Seal context.
pub struct EvpSeal {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    block_size: usize,
    iv: Vec<u8>,
    ek: Vec<Vec<u8>>,
}

/// Represents a EVP_Open context.
pub struct EvpOpen {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    block_size: usize,
}

impl EvpSeal {
    /// Creates a new `EvpSeal`.
    pub fn new(t: Cipher, pub_keys: Vec<PKey<Public>>) -> Result<EvpSeal, ErrorStack> {
        unsafe {
            let ctx = cvt_p(ffi::EVP_CIPHER_CTX_new())?;
            let mut ek = Vec::new();
            let mut pubk: Vec<*mut ffi::EVP_PKEY> = Vec::new();
            let mut my_ek = Vec::new();
            for key in &pub_keys {
                let mut key_buffer: Vec<c_uchar>;
                key_buffer = vec![0; ffi::EVP_PKEY_size(key.as_ptr()) as usize];
                let tmp = key_buffer.as_mut_ptr();
                my_ek.push(key_buffer);
                ek.push(tmp);
                pubk.push(key.as_ptr());
            }
            let mut iv_buffer: Vec<c_uchar> =
                vec![0; ffi::EVP_CIPHER_iv_length(t.as_ptr()) as usize];
            let mut ekl: Vec<c_int> = vec![0; ek.len()];

            cvt(ffi::EVP_SealInit(
                ctx,
                t.as_ptr(),
                ek.as_mut_ptr(),
                ekl.as_mut_ptr(),
                iv_buffer.as_mut_ptr(),
                pubk.as_mut_ptr(),
                pubk.len() as i32,
            ))?;
            Ok(EvpSeal {
                ctx,
                block_size: t.block_size(),
                iv: iv_buffer,
                ek: my_ek,
            })
        }
    }

    /// Return used initialization vector.
    pub fn iv(&self) -> &Vec<u8> {
        &self.iv
    }

    /// Return vector of keys encrypted by public key.
    pub fn ek(&self) -> &Vec<Vec<u8>> {
        &self.ek
    }

    /// Feeds data from `input` through the cipher, writing encrypted bytes into `output`.
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

    /// Returns block size of inner cipher.
    pub fn bs(&self) -> usize {
        self.block_size
    }
}

impl Drop for EvpSeal {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_CIPHER_CTX_free(self.ctx);
        }
    }
}

impl EvpOpen {
    /// Creates a new `EvpOpen`.
    pub fn new(
        t: Cipher,
        priv_key: &PKey<Private>,
        iv: &mut [u8],
        ek: &mut [u8],
    ) -> Result<EvpOpen, ErrorStack> {
        unsafe {
            let ctx = cvt_p(ffi::EVP_CIPHER_CTX_new())?;
            let ekl = ek.len() as c_int;

            cvt(ffi::EVP_OpenInit(
                ctx,
                t.as_ptr(),
                ek.as_ptr(),
                ekl,
                iv.as_mut_ptr(),
                priv_key.as_ptr(),
            ))?;
            Ok(EvpOpen {
                ctx,
                block_size: t.block_size(),
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

    /// Returns block size of inner cipher.
    pub fn bs(&self) -> usize {
        self.block_size
    }
}

impl Drop for EvpOpen {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_CIPHER_CTX_free(self.ctx);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pkey::PKey;
    use symm::Cipher;

    #[test]
    fn public_encrypt_private_decrypt() {
        let private_pem = include_bytes!("../test/rsa.pem");
        let public_pem = include_bytes!("../test/rsa.pem.pub");
        let private_key = PKey::private_key_from_pem(private_pem).unwrap();
        let public_key = PKey::public_key_from_pem(public_pem).unwrap();
        let cipher = Cipher::aes_256_cbc();
        let mut seal = EvpSeal::new(cipher, vec![public_key]).unwrap();
        let secret = b"My secret message";
        let mut encrypted = vec![0; secret.len() + seal.bs()];
        let mut enc_len = seal.update(secret, &mut encrypted).unwrap();
        enc_len += seal.finalize(&mut encrypted[enc_len..]).unwrap();
        let mut iv = seal.iv().clone();
        let encrypted_key = &seal.ek()[0].clone();

        let mut open =
            EvpOpen::new(cipher, &private_key, &mut iv, &mut encrypted_key.clone()).unwrap();
        let mut decrypted = vec![0; enc_len + open.bs()];
        let mut dec_len = open.update(&encrypted[..enc_len], &mut decrypted).unwrap();
        dec_len += open.finalize(&mut decrypted[dec_len..]).unwrap();

        assert_eq!(secret.len(), dec_len);
        assert_eq!(secret[..dec_len], decrypted[..dec_len]);
    }
}
