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
//! assert!(verifier.verify(&signature).unwrap());
//! ```
//!
//! Compute an HMAC:
//!
//! ```rust
//! use openssl::hash::MessageDigest;
//! use openssl::memcmp;
//! use openssl::pkey::PKey;
//! use openssl::sign::Signer;
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
//! let hmac = signer.sign_to_vec().unwrap();
//!
//! // `Verifier` cannot be used with HMACs; use the `memcmp::eq` function instead
//! //
//! // Do not simply check for equality with `==`!
//! # let target = hmac.clone();
//! assert!(memcmp::eq(&hmac, &target));
//! ```
use ffi;
use foreign_types::ForeignTypeRef;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::ptr;

use {cvt, cvt_p};
use hash::MessageDigest;
use pkey::{PKeyCtxRef, PKeyRef};
use error::ErrorStack;

#[cfg(ossl110)]
use ffi::{EVP_MD_CTX_free, EVP_MD_CTX_new};
#[cfg(any(ossl101, ossl102))]
use ffi::{EVP_MD_CTX_create as EVP_MD_CTX_new, EVP_MD_CTX_destroy as EVP_MD_CTX_free};

/// A type which computes cryptographic signatures of data.
pub struct Signer<'a> {
    md_ctx: *mut ffi::EVP_MD_CTX,
    pkey_ctx: *mut ffi::EVP_PKEY_CTX,
    pkey_pd: PhantomData<&'a PKeyRef>,
}

impl<'a> Drop for Signer<'a> {
    fn drop(&mut self) {
        // pkey_ctx is owned by the md_ctx, so no need to explicitly free it.
        unsafe {
            EVP_MD_CTX_free(self.md_ctx);
        }
    }
}

impl<'a> Signer<'a> {
    /// Creates a new `Signer`.
    ///
    /// OpenSSL documentation at [`EVP_DigestSignInit`].
    ///
    /// [`EVP_DigestSignInit`]: https://www.openssl.org/docs/manmaster/man3/EVP_DigestSignInit.html
    pub fn new(type_: MessageDigest, pkey: &'a PKeyRef) -> Result<Signer<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            let ctx = cvt_p(EVP_MD_CTX_new())?;
            let mut pctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
            let r = ffi::EVP_DigestSignInit(
                ctx,
                &mut pctx,
                type_.as_ptr(),
                ptr::null_mut(),
                pkey.as_ptr(),
            );
            if r != 1 {
                EVP_MD_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            assert!(!pctx.is_null());

            Ok(Signer {
                md_ctx: ctx,
                pkey_ctx: pctx,
                pkey_pd: PhantomData,
            })
        }
    }

    /// Returns a shared reference to the `PKeyCtx` associated with the `Signer`.
    pub fn pkey_ctx(&self) -> &PKeyCtxRef {
        unsafe { PKeyCtxRef::from_ptr(self.pkey_ctx) }
    }

    /// Returns a mutable reference to the `PKeyCtx` associated with the `Signer`.
    pub fn pkey_ctx_mut(&mut self) -> &mut PKeyCtxRef {
        unsafe { PKeyCtxRef::from_ptr_mut(self.pkey_ctx) }
    }

    /// Feeds more data into the `Signer`.
    ///
    /// OpenSSL documentation at [`EVP_DigestUpdate`].
    ///
    /// [`EVP_DigestUpdate`]: https://www.openssl.org/docs/manmaster/man3/EVP_DigestInit.html
    pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_DigestUpdate(
                self.md_ctx,
                buf.as_ptr() as *const _,
                buf.len(),
            )).map(|_| ())
        }
    }

    /// Computes an upper bound on the signature length.
    ///
    /// The actual signature may be shorter than this value. Check the return value of
    /// `sign` to get the exact length.
    ///
    /// OpenSSL documentation at [`EVP_DigestSignFinal`].
    ///
    /// [`EVP_DigestSignFinal`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_DigestSignFinal.html
    pub fn len(&self) -> Result<usize, ErrorStack> {
        unsafe {
            let mut len = 0;
            cvt(ffi::EVP_DigestSignFinal(
                self.md_ctx,
                ptr::null_mut(),
                &mut len,
            ))?;
            Ok(len)
        }
    }

    /// Writes the signature into the provided buffer, returning the number of bytes written.
    ///
    /// This method will fail if the buffer is not large enough for the signature. Use the `len`
    /// method to get an upper bound on the required size.
    ///
    /// OpenSSL documentation at [`EVP_DigestSignFinal`].
    ///
    /// [`EVP_DigestSignFinal`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_DigestSignFinal.html
    pub fn sign(&self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut len = buf.len();
            cvt(ffi::EVP_DigestSignFinal(
                self.md_ctx,
                buf.as_mut_ptr() as *mut _,
                &mut len,
            ))?;
            Ok(len)
        }
    }

    /// Returns the signature.
    ///
    /// This is a simple convenience wrapper over `len` and `sign`.
    pub fn sign_to_vec(&self) -> Result<Vec<u8>, ErrorStack> {
        let mut buf = vec![0; self.len()?];
        let len = self.sign(&mut buf)?;
        // The advertised length is not always equal to the real length for things like DSA
        buf.truncate(len);
        Ok(buf)
    }

    #[deprecated(since = "0.9.23", note = "renamed to sign_to_vec")]
    pub fn finish(&self) -> Result<Vec<u8>, ErrorStack> {
        self.sign_to_vec()
    }
}

impl<'a> Write for Signer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Verifier<'a> {
    md_ctx: *mut ffi::EVP_MD_CTX,
    pkey_ctx: *mut ffi::EVP_PKEY_CTX,
    pkey_pd: PhantomData<&'a PKeyRef>,
}

impl<'a> Drop for Verifier<'a> {
    fn drop(&mut self) {
        // pkey_ctx is owned by the md_ctx, so no need to explicitly free it.
        unsafe {
            EVP_MD_CTX_free(self.md_ctx);
        }
    }
}

/// A type which verifies cryptographic signatures of data.
impl<'a> Verifier<'a> {
    /// Creates a new `Verifier`.
    ///
    /// OpenSSL documentation at [`EVP_DigestVerifyInit`].
    ///
    /// [`EVP_DigestVerifyInit`]: https://www.openssl.org/docs/manmaster/man3/EVP_DigestVerifyInit.html
    pub fn new(type_: MessageDigest, pkey: &'a PKeyRef) -> Result<Verifier<'a>, ErrorStack> {
        unsafe {
            ffi::init();

            let ctx = cvt_p(EVP_MD_CTX_new())?;
            let mut pctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
            let r = ffi::EVP_DigestVerifyInit(
                ctx,
                &mut pctx,
                type_.as_ptr(),
                ptr::null_mut(),
                pkey.as_ptr(),
            );
            if r != 1 {
                EVP_MD_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            assert!(!pctx.is_null());

            Ok(Verifier {
                md_ctx: ctx,
                pkey_ctx: pctx,
                pkey_pd: PhantomData,
            })
        }
    }

    /// Returns a shared reference to the `PKeyCtx` associated with the `Verifier`.
    pub fn pkey_ctx(&self) -> &PKeyCtxRef {
        unsafe { PKeyCtxRef::from_ptr(self.pkey_ctx) }
    }

    /// Returns a mutable reference to the `PKeyCtx` associated with the `Verifier`.
    pub fn pkey_ctx_mut(&mut self) -> &mut PKeyCtxRef {
        unsafe { PKeyCtxRef::from_ptr_mut(self.pkey_ctx) }
    }

    /// Feeds more data into the `Verifier`.
    ///
    /// OpenSSL documentation at [`EVP_DigestUpdate`].
    ///
    /// [`EVP_DigestUpdate`]: https://www.openssl.org/docs/manmaster/man3/EVP_DigestInit.html
    pub fn update(&mut self, buf: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_DigestUpdate(
                self.md_ctx,
                buf.as_ptr() as *const _,
                buf.len(),
            )).map(|_| ())
        }
    }

    /// Determines if the data fed into the `Verifier` matches the provided signature.
    ///
    /// OpenSSL documentation at [`EVP_DigestVerifyFinal`].
    ///
    /// [`EVP_DigestVerifyFinal`]: https://www.openssl.org/docs/manmaster/man3/EVP_DigestVerifyFinal.html
    pub fn verify(&self, signature: &[u8]) -> Result<bool, ErrorStack> {
        unsafe {
            let r =
                EVP_DigestVerifyFinal(self.md_ctx, signature.as_ptr() as *const _, signature.len());
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

    #[deprecated(since = "0.9.23", note = "renamed to `verify`")]
    pub fn finish(&self, signature: &[u8]) -> Result<bool, ErrorStack> {
        self.verify(signature)
    }
}

impl<'a> Write for Verifier<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)?;
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
unsafe fn EVP_DigestVerifyFinal(
    ctx: *mut ffi::EVP_MD_CTX,
    sigret: *const ::libc::c_uchar,
    siglen: ::libc::size_t,
) -> ::libc::c_int {
    ffi::EVP_DigestVerifyFinal(ctx, sigret as *mut _, siglen)
}

#[cfg(test)]
mod test {
    use hex::{FromHex, ToHex};
    use std::iter;

    use hash::MessageDigest;
    use sign::{Signer, Verifier};
    use ec::{EcGroup, EcKey};
    use nid;
    use rsa::{PKCS1_PADDING, Rsa};
    use dsa::Dsa;
    use pkey::PKey;

    const INPUT: &'static str =
        "65794a68624763694f694a53557a49314e694a392e65794a7063334d694f694a71623255694c41304b49434a6c\
         654841694f6a457a4d4441344d546b7a4f44417344516f67496d6830644841364c79396c654746746347786c4c\
         6d4e76625339706331397962323930496a7030636e566c6651";

    const SIGNATURE: &'static str =
        "702e218943e88fd11eb5d82dbf7845f34106ae1b81fff7731116add1717d83656d420afd3c96eedd73a2663e51\
         66687b000b87226e0187ed1073f945e582adfcef16d85a798ee8c66ddb3db8975b17d09402beedd5d9d9700710\
         8db28160d5f8040ca7445762b81fbe7ff9d92e0ae76f24f25b33bbe6f44ae61eb1040acb20044d3ef9128ed401\
         30795bd4bd3b41eecad066ab651981fde48df77f372dc38b9fafdd3befb18b5da3cc3c2eb02f9e3a41d612caad\
         15911273a05f23b9e838faaf849d698429ef5a1e88798236c3d40e604522a544c8f27a7a2db80663d16cf7caea\
         56de405cb2215a45b2c25566b55ac1a748a070dfc8a32a469543d019eefb47";

    #[test]
    fn rsa_sign() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        assert_eq!(signer.pkey_ctx_mut().rsa_padding().unwrap(), PKCS1_PADDING);
        signer
            .pkey_ctx_mut()
            .set_rsa_padding(PKCS1_PADDING)
            .unwrap();
        signer.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        let result = signer.sign_to_vec().unwrap();

        assert_eq!(result.to_hex(), SIGNATURE);
    }

    #[test]
    fn rsa_verify_ok() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        assert_eq!(
            verifier.pkey_ctx_mut().rsa_padding().unwrap(),
            PKCS1_PADDING
        );
        verifier.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        assert!(verifier.verify(&Vec::from_hex(SIGNATURE).unwrap()).unwrap());
    }

    #[test]
    fn rsa_verify_invalid() {
        let key = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(key).unwrap();
        let pkey = PKey::from_rsa(private_key).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(&Vec::from_hex(INPUT).unwrap()).unwrap();
        verifier.update(b"foobar").unwrap();
        assert!(!verifier.verify(&Vec::from_hex(SIGNATURE).unwrap()).unwrap());
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
        let sig = signer.sign_to_vec().unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key).unwrap();
        verifier.update(&input).unwrap();
        assert!(verifier.verify(&sig).unwrap());
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
        let mut sig = signer.sign_to_vec().unwrap();
        sig[0] -= 1;

        let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key).unwrap();
        verifier.update(&input).unwrap();
        match verifier.verify(&sig) {
            Ok(true) => panic!("unexpected success"),
            Ok(false) | Err(_) => {}
        }
    }

    fn test_hmac(ty: MessageDigest, tests: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) {
        for &(ref key, ref data, ref res) in tests.iter() {
            let pkey = PKey::hmac(key).unwrap();
            let mut signer = Signer::new(ty, &pkey).unwrap();
            signer.update(data).unwrap();
            assert_eq!(signer.sign_to_vec().unwrap(), *res);
        }
    }

    #[test]
    fn hmac_md5() {
        // test vectors from RFC 2202
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 7] = [
            (
                iter::repeat(0x0b_u8).take(16).collect(),
                b"Hi There".to_vec(),
                Vec::from_hex("9294727a3638bb1c13f48ef8158bfc9d").unwrap(),
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                Vec::from_hex("750c783e6ab0b503eaa86e310a5db738").unwrap(),
            ),
            (
                iter::repeat(0xaa_u8).take(16).collect(),
                iter::repeat(0xdd_u8).take(50).collect(),
                Vec::from_hex("56be34521d144c88dbb8c733f0e8b3f6").unwrap(),
            ),
            (
                Vec::from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
                iter::repeat(0xcd_u8).take(50).collect(),
                Vec::from_hex("697eaf0aca3a3aea3a75164746ffaa79").unwrap(),
            ),
            (
                iter::repeat(0x0c_u8).take(16).collect(),
                b"Test With Truncation".to_vec(),
                Vec::from_hex("56461ef2342edc00f9bab995690efd4c").unwrap(),
            ),
            (
                iter::repeat(0xaa_u8).take(80).collect(),
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                Vec::from_hex("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd").unwrap(),
            ),
            (
                iter::repeat(0xaa_u8).take(80).collect(),
                b"Test Using Larger Than Block-Size Key \
              and Larger Than One Block-Size Data"
                    .to_vec(),
                Vec::from_hex("6f630fad67cda0ee1fb1f562db3aa53e").unwrap(),
            ),
        ];

        test_hmac(MessageDigest::md5(), &tests);
    }

    #[test]
    fn hmac_sha1() {
        // test vectors from RFC 2202
        let tests: [(Vec<u8>, Vec<u8>, Vec<u8>); 7] = [
            (
                iter::repeat(0x0b_u8).take(20).collect(),
                b"Hi There".to_vec(),
                Vec::from_hex("b617318655057264e28bc0b6fb378c8ef146be00").unwrap(),
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                Vec::from_hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap(),
            ),
            (
                iter::repeat(0xaa_u8).take(20).collect(),
                iter::repeat(0xdd_u8).take(50).collect(),
                Vec::from_hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3").unwrap(),
            ),
            (
                Vec::from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
                iter::repeat(0xcd_u8).take(50).collect(),
                Vec::from_hex("4c9007f4026250c6bc8414f9bf50c86c2d7235da").unwrap(),
            ),
            (
                iter::repeat(0x0c_u8).take(20).collect(),
                b"Test With Truncation".to_vec(),
                Vec::from_hex("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04").unwrap(),
            ),
            (
                iter::repeat(0xaa_u8).take(80).collect(),
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                Vec::from_hex("aa4ae5e15272d00e95705637ce8a3b55ed402112").unwrap(),
            ),
            (
                iter::repeat(0xaa_u8).take(80).collect(),
                b"Test Using Larger Than Block-Size Key \
              and Larger Than One Block-Size Data"
                    .to_vec(),
                Vec::from_hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91").unwrap(),
            ),
        ];

        test_hmac(MessageDigest::sha1(), &tests);
    }

    #[test]
    fn ec() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(b"hello world").unwrap();
        let signature = signer.sign_to_vec().unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        verifier.update(b"hello world").unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }
}
