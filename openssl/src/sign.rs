//! Message signatures.
//!
//! The `Signer` allows for the computation of cryptographic signatures of
//! data given a private key. The `Verifier` can then be used with the
//! corresponding public key to verify the integrity and authenticity of that
//! data given the signature.
//!
//! # Examples
//!
//! Sign and verify data given an RSA keypair:
//!
//! ```rust
//! use openssl::sign::{Signer, Verifier};
//! use openssl::rsa::Rsa;
//! use openssl::pkey::PKey;
//! use openssl::hash::MessageDigest;
//!
//! // Generate a keypair
//! let keypair = Rsa::generate(2048).unwrap();
//! let keypair = PKey::from_rsa(keypair).unwrap();
//!
//! let data = b"hello, world!";
//! let data2 = b"hola, mundo!";
//!
//! // Sign the data
//! let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
//! signer.update(data).unwrap();
//! signer.update(data2).unwrap();
//! let signature = signer.finish().unwrap();
//!
//! // Verify the data
//! let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
//! verifier.update(data).unwrap();
//! verifier.update(data2).unwrap();
//! assert!(verifier.finish(&signature).unwrap());
//! ```
//!
//! Compute an HMAC (note that `Verifier` cannot be used with HMACs):
//!
//! ```rust
//! use openssl::sign::Signer;
//! use openssl::pkey::PKey;
//! use openssl::hash::MessageDigest;
//!
//! // Create a PKey
//! let key = PKey::hmac(b"my secret").unwrap();
//!
//! let data = b"hello, world!";
//! let data2 = b"hola, mundo!";
//!
//! // Compute the HMAC
//! let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
//! signer.update(data).unwrap();
//! signer.update(data2).unwrap();
//! let hmac = signer.finish().unwrap();
//! ```
use ffi;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::ptr;

use {cvt, cvt_p};
use hash::MessageDigest;
use pkey::PKeyRef;
use error::ErrorStack;
use types::OpenSslTypeRef;

#[cfg(ossl110)]
use ffi::{EVP_MD_CTX_new, EVP_MD_CTX_free};
#[cfg(any(ossl101, ossl102))]
use ffi::{EVP_MD_CTX_create as EVP_MD_CTX_new, EVP_MD_CTX_destroy as EVP_MD_CTX_free};

pub struct Signer<'a>(*mut ffi::EVP_MD_CTX, PhantomData<&'a PKeyRef>);

impl<'a> Drop for Signer<'a> {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.0);
        }
    }
}

impl<'a> Signer<'a> {
    pub fn new(type_: MessageDigest, pkey: &'a PKeyRef) -> Result<Signer<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            let ctx = try!(cvt_p(EVP_MD_CTX_new()));
            let r = ffi::EVP_DigestSignInit(ctx,
                                            ptr::null_mut(),
                                            type_.as_ptr(),
                                            ptr::null_mut(),
                                            pkey.as_ptr());
            if r != 1 {
                EVP_MD_CTX_free(ctx);
                return Err(ErrorStack::get());
            }
            Ok(Signer(ctx, PhantomData))
        }
    }

    pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_DigestUpdate(self.0, buf.as_ptr() as *const _, buf.len())).map(|_| ())
        }
    }

    pub fn finish(&self) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let mut len = 0;
            try!(cvt(ffi::EVP_DigestSignFinal(self.0, ptr::null_mut(), &mut len)));
            let mut buf = vec![0; len];
            try!(cvt(ffi::EVP_DigestSignFinal(self.0, buf.as_mut_ptr() as *mut _, &mut len)));
            // The advertised length is not always equal to the real length for things like DSA
            buf.truncate(len);
            Ok(buf)
        }
    }
}

impl<'a> Write for Signer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try!(self.update(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Verifier<'a>(*mut ffi::EVP_MD_CTX, PhantomData<&'a PKeyRef>);

impl<'a> Drop for Verifier<'a> {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.0);
        }
    }
}

impl<'a> Verifier<'a> {
    pub fn new(type_: MessageDigest, pkey: &'a PKeyRef) -> Result<Verifier<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            let ctx = try!(cvt_p(EVP_MD_CTX_new()));
            let r = ffi::EVP_DigestVerifyInit(ctx,
                                              ptr::null_mut(),
                                              type_.as_ptr(),
                                              ptr::null_mut(),
                                              pkey.as_ptr());
            if r != 1 {
                EVP_MD_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            Ok(Verifier(ctx, PhantomData))
        }
    }

    pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_DigestUpdate(self.0, buf.as_ptr() as *const _, buf.len())).map(|_| ())
        }
    }

    pub fn finish(&self, signature: &[u8]) -> Result<bool, ErrorStack> {
        unsafe {
            let r = EVP_DigestVerifyFinal(self.0, signature.as_ptr() as *const _, signature.len());
            match r {
                1 => Ok(true),
                0 => {
                    ErrorStack::get(); // discard error stack
                    Ok(false)
                }
                _ => Err(ErrorStack::get()),
            }
        }
    }
}

impl<'a> Write for Verifier<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try!(self.update(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(not(ossl101))]
use ffi::EVP_DigestVerifyFinal;

#[cfg(ossl101)]
#[allow(bad_style)]
unsafe fn EVP_DigestVerifyFinal(ctx: *mut ffi::EVP_MD_CTX,
                                sigret: *const ::libc::c_uchar,
                                siglen: ::libc::size_t)
                                -> ::libc::c_int {
    ffi::EVP_DigestVerifyFinal(ctx, sigret as *mut _, siglen)
}

#[cfg(test)]
mod test {
    use hex::FromHex;
    use std::iter;

    use hash::MessageDigest;
    use sign::{Signer, Verifier};
    use rsa::Rsa;
    use dsa::Dsa;
    use pkey::PKey;

    static INPUT: &'static [u8] =
        &[101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 74, 57,
          46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48,
          75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107,
          122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76, 121, 57,
          108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83, 57, 112, 99, 49, 57,
          121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102, 81];

    static SIGNATURE: &'static [u8] =
        &[112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6, 174,
          27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10, 253, 60, 150,
          238, 221, 115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16,
          115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219, 61,
          184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7, 16, 141, 178, 129, 96,
          213, 248, 4, 12, 167, 68, 87, 98, 184, 31, 190, 127, 249, 217, 46, 10, 231, 111, 36,
          242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142,
          212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129, 253, 228,
          141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239, 177, 139, 93, 163, 204, 60, 46,
          176, 47, 158, 58, 65, 214, 18, 202, 173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56,
          250, 175, 132, 157, 105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69,
          34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64,
          92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163,
          42, 70, 149, 67, 208, 25, 238, 251, 71];

    #[test]
    fn rsa_sign() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(INPUT).unwrap();
        let result = signer.finish().unwrap();

        assert_eq!(result, SIGNATURE);
    }

    #[test]
    fn rsa_verify_ok() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(INPUT).unwrap();
        assert!(verifier.finish(SIGNATURE).unwrap());
    }

    #[test]
    fn rsa_verify_invalid() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(INPUT).unwrap();
        verifier.update(b"foobar").unwrap();
        assert!(!verifier.finish(SIGNATURE).unwrap());
    }

    #[test]
    pub fn dsa_sign_verify() {
        let input: Vec<u8> = (0..25).cycle().take(1024).collect();

        let private_key = {
            let key = include_bytes!("../test/dsa.pem");
            PKey::from_dsa(Dsa::private_key_from_pem(key).unwrap()).unwrap()
        };

        let public_key = {
            let key = include_bytes!("../test/dsa.pem.pub");
            PKey::from_dsa(Dsa::public_key_from_pem(key).unwrap()).unwrap()
        };

        let mut signer = Signer::new(MessageDigest::sha1(), &private_key).unwrap();
        signer.update(&input).unwrap();
        let sig = signer.finish().unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key).unwrap();
        verifier.update(&input).unwrap();
        assert!(verifier.finish(&sig).unwrap());
    }

    #[test]
    pub fn dsa_sign_verify_fail() {
        let input: Vec<u8> = (0..25).cycle().take(1024).collect();

        let private_key = {
            let key = include_bytes!("../test/dsa.pem");
            PKey::from_dsa(Dsa::private_key_from_pem(key).unwrap()).unwrap()
        };

        let public_key = {
            let key = include_bytes!("../test/dsa.pem.pub");
            PKey::from_dsa(Dsa::public_key_from_pem(key).unwrap()).unwrap()
        };

        let mut signer = Signer::new(MessageDigest::sha1(), &private_key).unwrap();
        signer.update(&input).unwrap();
        let mut sig = signer.finish().unwrap();
        sig[0] -= 1;

        let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key).unwrap();
        verifier.update(&input).unwrap();
        match verifier.finish(&sig) {
            Ok(true) => panic!("unexpected success"),
            Ok(false) | Err(_) => {}
        }
    }

    fn test_hmac(ty: MessageDigest, tests: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) {
        for &(ref key, ref data, ref res) in tests.iter() {
            let pkey = PKey::hmac(key).unwrap();
            let mut signer = Signer::new(ty, &pkey).unwrap();
            signer.update(data).unwrap();
            assert_eq!(signer.finish().unwrap(), *res);
        }
    }

    #[test]
    fn hmac_md5() {
        // test vectors from RFC 2202
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 7] =
            [(iter::repeat(0x0b_u8).take(16).collect(),
              b"Hi There".to_vec(),
              Vec::from_hex("9294727a3638bb1c13f48ef8158bfc9d").unwrap()),
             (b"Jefe".to_vec(),
              b"what do ya want for nothing?".to_vec(),
              Vec::from_hex("750c783e6ab0b503eaa86e310a5db738").unwrap()),
             (iter::repeat(0xaa_u8).take(16).collect(),
              iter::repeat(0xdd_u8).take(50).collect(),
              Vec::from_hex("56be34521d144c88dbb8c733f0e8b3f6").unwrap()),
             (Vec::from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
              iter::repeat(0xcd_u8).take(50).collect(),
              Vec::from_hex("697eaf0aca3a3aea3a75164746ffaa79").unwrap()),
             (iter::repeat(0x0c_u8).take(16).collect(),
              b"Test With Truncation".to_vec(),
              Vec::from_hex("56461ef2342edc00f9bab995690efd4c").unwrap()),
             (iter::repeat(0xaa_u8).take(80).collect(),
              b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
              Vec::from_hex("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd").unwrap()),
             (iter::repeat(0xaa_u8).take(80).collect(),
              b"Test Using Larger Than Block-Size Key \
              and Larger Than One Block-Size Data"
                 .to_vec(),
              Vec::from_hex("6f630fad67cda0ee1fb1f562db3aa53e").unwrap())];

        test_hmac(MessageDigest::md5(), &tests);
    }

    #[test]
    fn hmac_sha1() {
        // test vectors from RFC 2202
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 7] =
            [(iter::repeat(0x0b_u8).take(20).collect(),
              b"Hi There".to_vec(),
              Vec::from_hex("b617318655057264e28bc0b6fb378c8ef146be00").unwrap()),
             (b"Jefe".to_vec(),
              b"what do ya want for nothing?".to_vec(),
              Vec::from_hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap()),
             (iter::repeat(0xaa_u8).take(20).collect(),
              iter::repeat(0xdd_u8).take(50).collect(),
              Vec::from_hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3").unwrap()),
             (Vec::from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
              iter::repeat(0xcd_u8).take(50).collect(),
              Vec::from_hex("4c9007f4026250c6bc8414f9bf50c86c2d7235da").unwrap()),
             (iter::repeat(0x0c_u8).take(20).collect(),
              b"Test With Truncation".to_vec(),
              Vec::from_hex("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04").unwrap()),
             (iter::repeat(0xaa_u8).take(80).collect(),
              b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
              Vec::from_hex("aa4ae5e15272d00e95705637ce8a3b55ed402112").unwrap()),
             (iter::repeat(0xaa_u8).take(80).collect(),
              b"Test Using Larger Than Block-Size Key \
              and Larger Than One Block-Size Data"
                 .to_vec(),
              Vec::from_hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91").unwrap())];

        test_hmac(MessageDigest::sha1(), &tests);
    }
}
