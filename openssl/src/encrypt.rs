use std::{marker::PhantomData, ptr};

use error::ErrorStack;
use foreign_types::ForeignTypeRef;
use hash::MessageDigest;
use pkey::{HasPrivate, HasPublic, PKeyRef};
use rsa::Padding;
use {cvt, cvt_p};

pub struct Encrypter<'a> {
    pctx: *mut ffi::EVP_PKEY_CTX,
    _p: PhantomData<&'a ()>,
}

unsafe impl<'a> Sync for Encrypter<'a> {}
unsafe impl<'a> Send for Encrypter<'a> {}

impl<'a> Drop for Encrypter<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_PKEY_CTX_free(self.pctx);
        }
    }
}

impl<'a> Encrypter<'a> {
    /// Creates a new `Encrypter`.
    ///
    /// OpenSSL documentation at [`EVP_PKEY_encrypt_init`].
    ///
    /// [`EVP_PKEY_encrypt_init`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt_init.html
    pub fn new<T>(pkey: &'a PKeyRef<T>) -> Result<Encrypter<'a>, ErrorStack>
    where
        T: HasPublic,
    {
        unsafe {
            ffi::init();

            let pctx = cvt_p(ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut()))?;
            let r = ffi::EVP_PKEY_encrypt_init(pctx);
            if r != 1 {
                ffi::EVP_PKEY_CTX_free(pctx);
                return Err(ErrorStack::get());
            }

            Ok(Encrypter {
                pctx,
                _p: PhantomData,
            })
        }
    }

    /// Returns the RSA padding mode in use.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to `EVP_PKEY_CTX_get_rsa_padding`.
    pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
        unsafe {
            let mut pad = 0;
            cvt(ffi::EVP_PKEY_CTX_get_rsa_padding(self.pctx, &mut pad))
                .map(|_| Padding::from_raw(pad))
        }
    }

    /// Sets the RSA padding mode.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_padding`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_padding`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html
    pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_padding(
                self.pctx,
                padding.as_raw(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the RSA MGF1 algorithm.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_mgf1_md`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_mgf1_md`]: https://www.openssl.org/docs/manmaster/man7/RSA-PSS.html
    pub fn set_rsa_mgf1_md(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(
                self.pctx,
                md.as_ptr() as *mut _,
            ))
            .map(|_| ())
        }
    }

    /// Sets the RSA OAEP algorithm.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_oaep_md`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_oaep_md`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_CTX_set_rsa_oaep_md.html
    pub fn set_rsa_oaep_md(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_oaep_md(
                self.pctx,
                md.as_ptr() as *mut _,
            ))
            .map(|_| ())
        }
    }

    /// Performs public key encryption.
    ///
    /// This corresponds to [`EVP_PKEY_encrypt`].
    ///
    /// [`EVP_PKEY_encrypt`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt.html
    pub fn encrypt(&self, from: &[u8], to: &mut [u8]) -> Result<usize, ErrorStack> {
        let mut written = to.len();
        unsafe {
            cvt(ffi::EVP_PKEY_encrypt(
                self.pctx,
                to.as_mut_ptr(),
                &mut written,
                from.as_ptr(),
                from.len(),
            ))?;
        }

        Ok(written)
    }
}
pub struct Decrypter<'a> {
    pctx: *mut ffi::EVP_PKEY_CTX,
    _p: PhantomData<&'a ()>,
}

unsafe impl<'a> Sync for Decrypter<'a> {}
unsafe impl<'a> Send for Decrypter<'a> {}

impl<'a> Drop for Decrypter<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_PKEY_CTX_free(self.pctx);
        }
    }
}

impl<'a> Decrypter<'a> {
    /// Creates a new `Decrypter`.
    ///
    /// OpenSSL documentation at [`EVP_PKEY_decrypt_init`].
    ///
    /// [`EVP_PKEY_decrypt_init`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt_init.html
    pub fn new<T>(pkey: &'a PKeyRef<T>) -> Result<Decrypter<'a>, ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            ffi::init();

            let pctx = cvt_p(ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut()))?;
            let r = ffi::EVP_PKEY_decrypt_init(pctx);
            if r != 1 {
                ffi::EVP_PKEY_CTX_free(pctx);
                return Err(ErrorStack::get());
            }

            Ok(Decrypter {
                pctx,
                _p: PhantomData,
            })
        }
    }

    /// Returns the RSA padding mode in use.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to `EVP_PKEY_CTX_get_rsa_padding`.
    pub fn rsa_padding(&self) -> Result<Padding, ErrorStack> {
        unsafe {
            let mut pad = 0;
            cvt(ffi::EVP_PKEY_CTX_get_rsa_padding(self.pctx, &mut pad))
                .map(|_| Padding::from_raw(pad))
        }
    }

    /// Sets the RSA padding mode.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_padding`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_padding`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html
    pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_padding(
                self.pctx,
                padding.as_raw(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the RSA MGF1 algorithm.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_mgf1_md`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_mgf1_md`]: https://www.openssl.org/docs/manmaster/man7/RSA-PSS.html
    pub fn set_rsa_mgf1_md(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(
                self.pctx,
                md.as_ptr() as *mut _,
            ))
            .map(|_| ())
        }
    }

    /// Sets the RSA OAEP algorithm.
    ///
    /// This is only useful for RSA keys.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set_rsa_oaep_md`].
    ///
    /// [`EVP_PKEY_CTX_set_rsa_oaep_md`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_CTX_set_rsa_oaep_md.html
    pub fn set_rsa_oaep_md(&mut self, md: MessageDigest) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_rsa_oaep_md(
                self.pctx,
                md.as_ptr() as *mut _,
            ))
            .map(|_| ())
        }
    }

    /// Performs public key decryption.
    ///
    /// This corresponds to [`EVP_PKEY_decrypt`].
    ///
    /// [`EVP_PKEY_decrypt`]: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt.html
    pub fn decrypt(&self, from: &[u8], to: &mut [u8]) -> Result<usize, ErrorStack> {
        let mut written = to.len();
        unsafe {
            cvt(ffi::EVP_PKEY_decrypt(
                self.pctx,
                to.as_mut_ptr(),
                &mut written,
                from.as_ptr(),
                from.len(),
            ))?;
        }

        Ok(written)
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use encrypt::{Decrypter, Encrypter};
    use hash::MessageDigest;
    use pkey::PKey;
    use rsa::{Padding, Rsa};

    const INPUT: &str =
        "65794a68624763694f694a53557a49314e694a392e65794a7063334d694f694a71623255694c41304b49434a6c\
         654841694f6a457a4d4441344d546b7a4f44417344516f67496d6830644841364c79396c654746746347786c4c\
         6d4e76625339706331397962323930496a7030636e566c6651";

    #[test]
    fn rsa_encrypt_decrypt() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut encrypter = Encrypter::new(&pkey).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1).unwrap();
        let input = Vec::from_hex(INPUT).unwrap();
        let mut encoded = vec![0u8; INPUT.len() * 3];
        let encoded_len = encrypter.encrypt(&input, &mut encoded).unwrap();
        let encoded = &encoded[..encoded_len];

        let mut decrypter = Decrypter::new(&pkey).unwrap();
        decrypter.set_rsa_padding(Padding::PKCS1).unwrap();
        let mut decoded = vec![0u8; encoded.len()];
        let decoded_len = decrypter.decrypt(&encoded, &mut decoded).unwrap();
        let decoded = &decoded[..decoded_len];

        assert_eq!(decoded, &*input);
    }

    #[test]
    fn rsa_encrypt_decrypt_with_sha256() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let md = MessageDigest::sha256();

        let mut encrypter = Encrypter::new(&pkey).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(md).unwrap();
        encrypter.set_rsa_mgf1_md(md).unwrap();
        let input = Vec::from_hex(INPUT).unwrap();
        let mut encoded = vec![0u8; INPUT.len() * 3];
        let encoded_len = encrypter.encrypt(&input, &mut encoded).unwrap();
        let encoded = &encoded[..encoded_len];

        let mut decrypter = Decrypter::new(&pkey).unwrap();
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        decrypter.set_rsa_oaep_md(md).unwrap();
        decrypter.set_rsa_mgf1_md(md).unwrap();
        let mut decoded = vec![0u8; encoded.len()];
        let decoded_len = decrypter.decrypt(&encoded, &mut decoded).unwrap();
        let decoded = &decoded[..decoded_len];

        assert_eq!(decoded, &*input);
    }
}
