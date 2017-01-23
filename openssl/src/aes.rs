//! Low level AES functionality
//!
//! The `symm` module should be used in preference to this module in most cases.
use ffi;
use std::mem;
use libc::c_int;

use symm::Mode;

#[derive(Debug)]
pub struct KeyError(());

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
            let r = ffi::AES_set_encrypt_key(key.as_ptr() as *const _,
                                             key.len() as c_int * 8,
                                             &mut aes_key);
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
            let r = ffi::AES_set_decrypt_key(key.as_ptr() as *const _,
                                             key.len() as c_int * 8,
                                             &mut aes_key);

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
        ffi::AES_ige_encrypt(in_.as_ptr() as *const _,
                             out.as_mut_ptr() as *mut _,
                             in_.len(),
                             &key.0,
                             iv.as_mut_ptr() as *mut _,
                             mode);
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use symm::Mode;
    use super::*;

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
