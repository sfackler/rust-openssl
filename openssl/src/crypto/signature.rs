// Copyright (c) 2016, The rust-openssl developers.

//! Interface for computing/verifying message signatures
//!
//! The `Signer` allows for the computation of crytographic signatures
//! of data given a private key.  The corresponding public key can then
//! be used to verify the integrity and authenticity of signed messages
//! using the `Verifier`.
//!
//! # Example
//!
//! ```rust
//! use std::io::prelude::*;
//! use openssl::crypto::signature::{Signer, Verifier};
//! use openssl::crypto::pkey::PKey;
//! use openssl::crypto::hash;
//!
//! // Generate public/private keypairs
//! let mut keypair = PKey::new();
//! let mut privkey = PKey::new();
//! let mut pubkey = PKey::new();
//! keypair.gen(1024);
//! privkey.load_priv(&keypair.save_priv()[..]);
//! pubkey.load_pub(&keypair.save_pub()[..]);
//!
//! // generate some data
//! let data1: Vec<u8> = (0..25).cycle().take(1024).collect();
//! let data2: Vec<u8> = (100..150).cycle().take(1024 * 5).collect();
//!
//! // sign some content with private key
//! let mut signer = Signer::new(hash::Type::SHA512, &privkey).unwrap();
//! signer.write_all(&data1[..]).unwrap();
//! signer.write_all(&data2[..]).unwrap();
//! let signature = signer.finish().unwrap();
//!
//! // verify content using signature and public key
//! let mut verifier = Verifier::new(hash::Type::SHA512, &pubkey).unwrap();
//! verifier.write_all(&data1[..]).unwrap();
//! verifier.write_all(&data2[..]).unwrap();
//! assert!(verifier.finish(&signature[..]).unwrap());
//! ```

use std::ptr;
use std::io::{self, Write};
use std::marker::PhantomData;
use libc;

use ffi;
use ssl::error::SslError;
use crypto::pkey::PKey;
use crypto::hash;

/// Signature Generation Context
pub struct Signer<'a> {
    ctx: *mut ffi::EVP_MD_CTX,
    pkey: PhantomData<&'a PKey>,
}

/// Signature Verification Context
pub struct Verifier<'a> {
    ctx: *mut ffi::EVP_MD_CTX,
    pkey: PhantomData<&'a PKey>,
}

impl<'a> Signer<'a> {
    /// Create and initialize a new Signer
    ///
    /// The digest type specified will determine the final form  of the
    /// signature returned by `finalize`.
    pub fn new(digest_type: hash::Type, pkey: &'a PKey) -> Result<Signer, SslError> {
        ffi::init();

        let ctx = unsafe {
            let r = ffi::EVP_MD_CTX_create();
            assert!(!r.is_null(), "EVP_MD_CTX_create failed");
            r
        };

        let md = digest_type.evp_md();

        unsafe {
            try_ssl_if!(1 !=
                        ffi::EVP_DigestSignInit(ctx,
                                                ptr::null_mut(),
                                                md,
                                                ptr::null(),
                                                pkey.get_handle()));
        }

        Ok(Signer {
            ctx: ctx,
            pkey: PhantomData,
        })
    }

    /// Feed bytes to be added to the signature calculation
    #[inline]
    fn update(&mut self, data: &[u8]) -> Result<(), SslError> {
        unsafe {
            lift_ssl_if!(1 != ffi::EVP_DigestUpdate(self.ctx, data.as_ptr(), data.len() as u32))
        }
    }

    /// Finalize the signature calculation and return the signature
    ///
    /// The signature form will be determined by the hashing type for this
    /// Signer (e.g. `SHA512` will return a Vector with 64 bytes).
    #[inline]
    pub fn finish(&mut self) -> Result<Vec<u8>, SslError> {
        let mut sigbuf = [0u8; 8 * 1024];
        let mut siglen = sigbuf.len() as libc::size_t;
        unsafe {
            try_ssl_if!(1 !=
                        ffi::EVP_DigestSignFinal(self.ctx,
                                                 (&mut sigbuf[..]).as_mut_ptr(),
                                                 &mut siglen));
        }
        Ok(Vec::from(&sigbuf[..siglen]))
    }
}

impl<'a> Write for Signer<'a> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let len = ::std::cmp::min(data.len(), u32::max_value() as usize);
        try!(self.update(&data[..len]));
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Drop for Signer<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_MD_CTX_destroy(self.ctx);
        }
    }
}

impl<'a> Verifier<'a> {
    /// Create and initialize a new Verifier
    ///
    /// The digest type should match the form of the signature provided
    /// during the final step of signature verification.
    pub fn new(digest_type: hash::Type, pkey: &'a PKey) -> Result<Verifier, SslError> {
        ffi::init();

        let ctx = unsafe {
            let r = ffi::EVP_MD_CTX_create();
            assert!(!r.is_null(), "EVP_MD_CTX_create failed");
            r
        };

        let md = digest_type.evp_md();

        unsafe {
            try_ssl_if!(1 !=
                        ffi::EVP_DigestVerifyInit(ctx,
                                                  ptr::null_mut(),
                                                  md,
                                                  ptr::null_mut(),
                                                  pkey.get_handle()));
        }

        Ok(Verifier {
            ctx: ctx,
            pkey: PhantomData,
        })
    }

    /// Feed bytes into the verification calculation
    #[inline]
    fn update(&mut self, data: &[u8]) -> Result<(), SslError> {
        unsafe {
            lift_ssl_if!(1 != ffi::EVP_DigestUpdate(self.ctx, data.as_ptr(), data.len() as u32))
        }
    }

    /// Verify that the content feed into this Verifier is valid for the
    /// given signature
    #[inline]
    pub fn finish(&self, signature: &[u8]) -> Result<bool, SslError> {
        let r = unsafe {
            ffi::EVP_DigestVerifyFinal(self.ctx,
                                       signature.as_ptr(),
                                       signature.len() as libc::size_t)
        };
        match r {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(SslError::get()),
        }
    }
}

impl<'a> Write for Verifier<'a> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let len = ::std::cmp::min(data.len(), u32::max_value() as usize);
        try!(self.update(&data[..len]));
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Drop for Verifier<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_MD_CTX_destroy(self.ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::prelude::*;
    use crypto::hash;
    use crypto::pkey::PKey;

    #[test]
    fn test_sign_verify() {
        // Generate public/private keypairs
        let mut keypair = PKey::new();
        let mut pubkey = PKey::new();
        let mut privkey = PKey::new();
        keypair.gen(1024);
        privkey.load_priv(&keypair.save_priv()[..]);
        pubkey.load_pub(&keypair.save_pub()[..]);

        // generate some data
        let data1: Vec<u8> = (0..25).cycle().take(1024).collect();
        let data2: Vec<u8> = (100..150).cycle().take(1024 * 5).collect();

        // sign some content with private key
        let mut signer = Signer::new(hash::Type::SHA224, &privkey).unwrap();
        signer.write_all(&data1[..]).unwrap();
        signer.write_all(&data2[..]).unwrap();
        let signature = signer.finish().unwrap();

        // verify content using signature and public key
        let mut verifier = Verifier::new(hash::Type::SHA224, &pubkey).unwrap();
        verifier.write_all(&data1[..]).unwrap();
        verifier.write_all(&data2[..]).unwrap();
        assert!(verifier.finish(&signature[..]).unwrap());
    }

    #[test]
    fn test_sign_verify_fail() {
        // Generate public/private keypairs
        let mut keypair = PKey::new();
        let mut privkey = PKey::new();
        let mut pubkey = PKey::new();
        keypair.gen(1024);
        privkey.load_priv(&keypair.save_priv()[..]);
        pubkey.load_pub(&keypair.save_pub()[..]);

        // generate some data
        let data1: Vec<u8> = (0..25).cycle().take(1024).collect();
        let data2: Vec<u8> = (100..150).cycle().take(1024 * 5).collect();

        // sign some content with private key
        let mut signer = Signer::new(hash::Type::SHA224, &privkey).unwrap();
        signer.write_all(&data1[..]).unwrap();
        signer.write_all(&data2[..]).unwrap();
        let signature = signer.finish().unwrap();

        // verify content using signature and public key
        let mut verifier = Verifier::new(hash::Type::SHA224, &pubkey).unwrap();
        verifier.write_all(&data1[..]).unwrap();
        verifier.write_all(&data2[..]).unwrap();

        // NOTE: here we inject a few extra bytes.  This should make the signature
        // check fail (the contents have been tampered with)
        verifier.write_all(&[1, 2, 3]).unwrap();
        assert!(!verifier.finish(&signature[..]).unwrap());
    }

}
