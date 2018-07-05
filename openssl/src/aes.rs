//! Low level AES IGE functionality
//!
//! AES ECB, CBC, XTS, CTR, CFB, GCM and other conventional symmetric encryption
//! modes are found in [`symm`].  This is the implementation of AES IGE.
//!
//! Advanced Encryption Standard (AES) provides symmetric key cipher that
//! the same key is used to encrypt and decrypt data.  This implementation
//! uses 128, 192, or 256 bit keys.  This module provides functions to
//! create a new key with [`new_encrypt`] and perform an encryption/decryption
//! using that key with [`aes_ige`].
//!
//! [`new_encrypt`]: struct.AesKey.html#method.new_encrypt
//! [`aes_ige`]: fn.aes_ige.html
//!
//! The [`symm`] module should be used in preference to this module in most cases.
//! The IGE block cypher is a non-traditional cipher mode.  More traditional AES
//! encryption methods are found in the [`Crypter`] and [`Cipher`] structs.
//!
//! [`symm`]: ../symm/index.html
//! [`Crypter`]: ../symm/struct.Crypter.html
//! [`Cipher`]: ../symm/struct.Cipher.html
//!
//! # Examples
//!
//! ```rust
//! use openssl::aes::{AesKey, aes_ige};
//! use openssl::symm::Mode;
//!
//! let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//! let plaintext = b"\x12\x34\x56\x78\x90\x12\x34\x56\x12\x34\x56\x78\x90\x12\x34\x56";
//! let mut iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
//!                 \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
//!
//!  let key = AesKey::new_encrypt(key).unwrap();
//!  let mut output = [0u8; 16];
//!  aes_ige(plaintext, &mut output, &key, &mut iv, Mode::Encrypt);
//!  assert_eq!(output, *b"\xa6\xad\x97\x4d\x5c\xea\x1d\x36\xd2\xf3\x67\x98\x09\x07\xed\x32");
use ffi;
use libc::c_int;
use std::mem;

use symm::Mode;

/// Provides Error handling for parsing keys.
#[derive(Debug)]
pub struct KeyError(());

/// The key used to encrypt or decrypt cipher blocks.
pub struct AesKey(ffi::AES_KEY);

impl AesKey {
    /// Prepares a key for encryption.
    ///
    /// # Failure
    ///
    /// Returns an error if the key is not 128, 192, or 256 bits.
    pub fn new_encrypt(key: &[u8]) -> Result<AesKey, KeyError> {
        unsafe {
            assert!(key.len() <= c_int::max_value() as usize / 8);

            let mut aes_key = mem::uninitialized();
            let r = ffi::AES_set_encrypt_key(
                key.as_ptr() as *const _,
                key.len() as c_int * 8,
                &mut aes_key,
            );
            if r == 0 {
                Ok(AesKey(aes_key))
            } else {
                Err(KeyError(()))
            }
        }
    }

    /// Prepares a key for decryption.
    ///
    /// # Failure
    ///
    /// Returns an error if the key is not 128, 192, or 256 bits.
    pub fn new_decrypt(key: &[u8]) -> Result<AesKey, KeyError> {
        unsafe {
            assert!(key.len() <= c_int::max_value() as usize / 8);

            let mut aes_key = mem::uninitialized();
            let r = ffi::AES_set_decrypt_key(
                key.as_ptr() as *const _,
                key.len() as c_int * 8,
                &mut aes_key,
            );

            if r == 0 {
                Ok(AesKey(aes_key))
            } else {
                Err(KeyError(()))
            }
        }
    }
}

/// Performs AES IGE encryption or decryption
///
/// AES IGE (Infinite Garble Extension) is a form of AES block cipher utilized in
/// OpenSSL.  Infinite Garble referes to propogating forward errors.  IGE, like other
/// block ciphers implemented for AES requires an initalization vector.  The IGE mode
/// allows a stream of blocks to be encrypted or decrypted without having the entire
/// plaintext available.  For more information, visit [AES IGE Encryption].
///
/// This block cipher uses 16 byte blocks.  The rust implmentation will panic
/// if the input or output does not meet this 16-byte boundry.  Attention must
/// be made in this low level implementation to pad the value to the 128-bit boundry.
///
/// [AES IGE Encryption]: http://www.links.org/files/openssl-ige.pdf
///
/// # Panics
///
/// Panics if `in_` is not the same length as `out`, if that length is not a multiple of 16, or if
/// `iv` is not at least 32 bytes.
pub fn aes_ige(in_: &[u8], out: &mut [u8], key: &AesKey, iv: &mut [u8], mode: Mode) {
    unsafe {
        assert!(in_.len() == out.len());
        assert!(in_.len() % ffi::AES_BLOCK_SIZE as usize == 0);
        assert!(iv.len() >= ffi::AES_BLOCK_SIZE as usize * 2);

        let mode = match mode {
            Mode::Encrypt => ffi::AES_ENCRYPT,
            Mode::Decrypt => ffi::AES_DECRYPT,
        };
        ffi::AES_ige_encrypt(
            in_.as_ptr() as *const _,
            out.as_mut_ptr() as *mut _,
            in_.len(),
            &key.0,
            iv.as_mut_ptr() as *mut _,
            mode,
        );
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;
    use symm::Mode;

    // From https://www.mgp25.com/AESIGE/
    #[test]
    fn ige_vector_1() {
        let raw_key = "000102030405060708090A0B0C0D0E0F";
        let raw_iv = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        let raw_pt = "0000000000000000000000000000000000000000000000000000000000000000";
        let raw_ct = "1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB";

        let key = AesKey::new_encrypt(&Vec::from_hex(raw_key).unwrap()).unwrap();
        let mut iv = Vec::from_hex(raw_iv).unwrap();
        let pt = Vec::from_hex(raw_pt).unwrap();
        let ct = Vec::from_hex(raw_ct).unwrap();

        let mut ct_actual = vec![0; ct.len()];
        aes_ige(&pt, &mut ct_actual, &key, &mut iv, Mode::Encrypt);
        assert_eq!(ct_actual, ct);

        let key = AesKey::new_decrypt(&Vec::from_hex(raw_key).unwrap()).unwrap();
        let mut iv = Vec::from_hex(raw_iv).unwrap();
        let mut pt_actual = vec![0; pt.len()];
        aes_ige(&ct, &mut pt_actual, &key, &mut iv, Mode::Decrypt);
        assert_eq!(pt_actual, pt);
    }
}
