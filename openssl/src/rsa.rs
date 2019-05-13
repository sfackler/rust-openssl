//! Rivest–Shamir–Adleman cryptosystem
//!
//! RSA is one of the earliest asymmetric public key encryption schemes.
//! Like many other cryptosystems, RSA relies on the presumed difficulty of a hard
//! mathematical problem, namely factorization of the product of two large prime
//! numbers. At the moment there does not exist an algorithm that can factor such
//! large numbers in reasonable time. RSA is used in a wide variety of
//! applications including digital signatures and key exchanges such as
//! establishing a TLS/SSL connection.
//!
//! The RSA acronym is derived from the first letters of the surnames of the
//! algorithm's founding trio.
//!
//! # Example
//!
//! Generate a 2048-bit RSA key pair and use the public key to encrypt some data.
//!
//! ```rust
//!
//! extern crate openssl;
//!
//! use openssl::rsa::{Rsa, Padding};
//!
//! fn main() {
//!     let rsa = Rsa::generate(2048).unwrap();
//!     let data = b"foobar";
//!     let mut buf = vec![0; rsa.size() as usize];
//!     let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
//! }
//! ```
#![allow(non_snake_case)]

use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_uchar, c_uint, c_void};
use std::ffi::{CStr, CString};
use std::fmt;
use std::mem;
use std::ptr;

use bn::{BigNum, BigNumRef};
use error::ErrorStack;
use ex_data::{free_data_box, Index};
use pkey::{HasPrivate, HasPublic, Private, Public};
use engine::EngineRef;
use {cvt, cvt_n, cvt_p};

/// Type of encryption padding to use.
///
/// Random length padding is primarily used to prevent attackers from
/// predicting or knowing the exact length of a plaintext message that
/// can possibly lead to breaking encryption.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Padding(c_int);

impl Padding {
    /// Creates a `Padding` from an integer representation.
    pub fn from_raw(value: c_int) -> Padding {
        Padding(value)
    }

    /// Returns the integer representation of `Padding`.
    pub fn as_raw(&self) -> c_int {
        self.0
    }

    pub const NONE: Padding = Padding(ffi::RSA_NO_PADDING);
    pub const PKCS1: Padding = Padding(ffi::RSA_PKCS1_PADDING);
    pub const PKCS1_OAEP: Padding = Padding(ffi::RSA_PKCS1_OAEP_PADDING);
    pub const PKCS1_PSS: Padding = Padding(ffi::RSA_PKCS1_PSS_PADDING);
}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::RSA;
    fn drop = ffi::RSA_free;

    /// An RSA key.
    pub struct Rsa<T>;

    /// Reference to `RSA`
    pub struct RsaRef<T>;
}

impl<T> Clone for Rsa<T> {
    fn clone(&self) -> Rsa<T> {
        (**self).to_owned()
    }
}

impl<T> ToOwned for RsaRef<T> {
    type Owned = Rsa<T>;

    fn to_owned(&self) -> Rsa<T> {
        unsafe {
            ffi::RSA_up_ref(self.as_ptr());
            Rsa::from_ptr(self.as_ptr())
        }
    }
}

impl<T> RsaRef<T>
where
    T: HasPrivate,
{
    private_key_to_pem! {
        /// Serializes the private key to a PEM-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
        ///
        /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
        private_key_to_pem,
        /// Serializes the private key to a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
        ///
        /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
        private_key_to_pem_passphrase,
        ffi::PEM_write_bio_RSAPrivateKey
    }

    to_der! {
        /// Serializes the private key to a DER-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`i2d_RSAPrivateKey`].
        ///
        /// [`i2d_RSAPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_RSAPrivateKey.html
        private_key_to_der,
        ffi::i2d_RSAPrivateKey
    }

    /// Decrypts data using the private key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    pub fn private_decrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_private_decrypt(
                from.len() as c_int,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Encrypts data using the private key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    pub fn private_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_private_encrypt(
                from.len() as c_int,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Returns a reference to the private exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_key`].
    ///
    /// [`RSA_get0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn d(&self) -> &BigNumRef {
        unsafe {
            let mut d = ptr::null();
            RSA_get0_key(self.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut d);
            BigNumRef::from_ptr(d as *mut _)
        }
    }

    /// Returns a reference to the first factor of the exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_factors`].
    ///
    /// [`RSA_get0_factors`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn p(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut p = ptr::null();
            RSA_get0_factors(self.as_ptr(), &mut p, ptr::null_mut());
            if p.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(p as *mut _))
            }
        }
    }

    /// Returns a reference to the second factor of the exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_factors`].
    ///
    /// [`RSA_get0_factors`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn q(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut q = ptr::null();
            RSA_get0_factors(self.as_ptr(), ptr::null_mut(), &mut q);
            if q.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(q as *mut _))
            }
        }
    }

    /// Returns a reference to the first exponent used for CRT calculations.
    ///
    /// This corresponds to [`RSA_get0_crt_params`].
    ///
    /// [`RSA_get0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn dmp1(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut dp = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), &mut dp, ptr::null_mut(), ptr::null_mut());
            if dp.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(dp as *mut _))
            }
        }
    }

    /// Returns a reference to the second exponent used for CRT calculations.
    ///
    /// This corresponds to [`RSA_get0_crt_params`].
    ///
    /// [`RSA_get0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn dmq1(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut dq = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), ptr::null_mut(), &mut dq, ptr::null_mut());
            if dq.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(dq as *mut _))
            }
        }
    }

    /// Returns a reference to the coefficient used for CRT calculations.
    ///
    /// This corresponds to [`RSA_get0_crt_params`].
    ///
    /// [`RSA_get0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn iqmp(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut qi = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut qi);
            if qi.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(qi as *mut _))
            }
        }
    }

    /// Validates RSA parameters for correctness
    ///
    /// This corresponds to [`RSA_check_key`].
    ///
    /// [`RSA_check_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_check_key.html
    pub fn check_key(&self) -> Result<bool, ErrorStack> {
        unsafe {
            let result = ffi::RSA_check_key(self.as_ptr()) as i32;
            if result == -1 {
                Err(ErrorStack::get())
            } else {
                Ok(result == 1)
            }
        }
    }

    #[cfg(ossl110)]
    pub fn engine(&self) -> &EngineRef {
        unsafe { EngineRef::from_ptr(ffi::RSA_get0_engine(self.as_ptr())) }
    }

    #[cfg(not(ossl110))]
    pub fn engine(&self) -> &EngineRef {
        unsafe { EngineRef::from_ptr(self.engine) }
    }

    pub fn method(&self) -> &RsaMethodRef {
        unsafe { RsaMethodRef::from_ptr(ffi::RSA_get_method(self.as_ptr()) as *mut _) }
    }

    pub fn set_method(&self, method: &RsaMethod) -> Result<(), ErrorStack> {
        cvt(unsafe { ffi::RSA_set_method(self.as_ptr(), method.as_ptr()) }).map(|_| ())
    }
}

impl<T> RsaRef<T>
where
    T: HasPublic,
{
    to_pem! {
        /// Serializes the public key into a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSA_PUBKEY`].
        ///
        /// [`PEM_write_bio_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.0.2/crypto/pem.html
        public_key_to_pem,
        ffi::PEM_write_bio_RSA_PUBKEY
    }

    to_der! {
        /// Serializes the public key into a DER-encoded SubjectPublicKeyInfo structure.
        ///
        /// This corresponds to [`i2d_RSA_PUBKEY`].
        ///
        /// [`i2d_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.1.0/crypto/i2d_RSA_PUBKEY.html
        public_key_to_der,
        ffi::i2d_RSA_PUBKEY
    }

    to_pem! {
        /// Serializes the public key into a PEM-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSAPublicKey`].
        ///
        /// [`PEM_write_bio_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/pem.html
        public_key_to_pem_pkcs1,
        ffi::PEM_write_bio_RSAPublicKey
    }

    to_der! {
        /// Serializes the public key into a DER-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// This corresponds to [`i2d_RSAPublicKey`].
        ///
        /// [`i2d_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_RSAPublicKey.html
        public_key_to_der_pkcs1,
        ffi::i2d_RSAPublicKey
    }

    /// Returns the size of the modulus in bytes.
    ///
    /// This corresponds to [`RSA_size`].
    ///
    /// [`RSA_size`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_size.html
    pub fn size(&self) -> u32 {
        unsafe { ffi::RSA_size(self.as_ptr()) as u32 }
    }

    /// Decrypts data using the public key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    pub fn public_decrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_public_decrypt(
                from.len() as c_int,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Encrypts data using the public key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    pub fn public_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_public_encrypt(
                from.len() as c_int,
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Returns a reference to the modulus of the key.
    ///
    /// This corresponds to [`RSA_get0_key`].
    ///
    /// [`RSA_get0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn n(&self) -> &BigNumRef {
        unsafe {
            let mut n = ptr::null();
            RSA_get0_key(self.as_ptr(), &mut n, ptr::null_mut(), ptr::null_mut());
            BigNumRef::from_ptr(n as *mut _)
        }
    }

    /// Returns a reference to the public exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_key`].
    ///
    /// [`RSA_get0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn e(&self) -> &BigNumRef {
        unsafe {
            let mut e = ptr::null();
            RSA_get0_key(self.as_ptr(), ptr::null_mut(), &mut e, ptr::null_mut());
            BigNumRef::from_ptr(e as *mut _)
        }
    }
}

impl Rsa<Public> {
    /// Creates a new RSA key with only public components.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent.
    ///
    /// This corresponds to [`RSA_new`] and uses [`RSA_set0_key`].
    ///
    /// [`RSA_new`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_new.html
    /// [`RSA_set0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_key.html
    pub fn from_public_components(n: BigNum, e: BigNum) -> Result<Rsa<Public>, ErrorStack> {
        unsafe {
            let rsa = cvt_p(ffi::RSA_new())?;
            RSA_set0_key(rsa, n.as_ptr(), e.as_ptr(), ptr::null_mut());
            mem::forget((n, e));
            Ok(Rsa::from_ptr(rsa))
        }
    }

    from_pem! {
        /// Decodes a PEM-encoded SubjectPublicKeyInfo structure containing an RSA key.
        ///
        /// The input should have a header of `-----BEGIN PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_read_bio_RSA_PUBKEY`].
        ///
        /// [`PEM_read_bio_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_RSA_PUBKEY.html
        public_key_from_pem,
        Rsa<Public>,
        ffi::PEM_read_bio_RSA_PUBKEY
    }

    from_pem! {
        /// Decodes a PEM-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// The input should have a header of `-----BEGIN RSA PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPublicKey`].
        ///
        /// [`PEM_read_bio_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_RSAPublicKey.html
        public_key_from_pem_pkcs1,
        Rsa<Public>,
        ffi::PEM_read_bio_RSAPublicKey
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure containing an RSA key.
        ///
        /// This corresponds to [`d2i_RSA_PUBKEY`].
        ///
        /// [`d2i_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_RSA_PUBKEY.html
        public_key_from_der,
        Rsa<Public>,
        ffi::d2i_RSA_PUBKEY
    }

    from_der! {
        /// Decodes a DER-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// This corresponds to [`d2i_RSAPublicKey`].
        ///
        /// [`d2i_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_RSA_PUBKEY.html
        public_key_from_der_pkcs1,
        Rsa<Public>,
        ffi::d2i_RSAPublicKey
    }
}

pub struct RsaPrivateKeyBuilder {
    rsa: Rsa<Private>,
}

impl RsaPrivateKeyBuilder {
    /// Creates a new `RsaPrivateKeyBuilder`.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent and `d` is the private exponent.
    ///
    /// This corresponds to [`RSA_new`] and uses [`RSA_set0_key`].
    ///
    /// [`RSA_new`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_new.html
    /// [`RSA_set0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_key.html
    pub fn new(n: BigNum, e: BigNum, d: BigNum) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            let rsa = cvt_p(ffi::RSA_new())?;
            RSA_set0_key(rsa, n.as_ptr(), e.as_ptr(), d.as_ptr());
            mem::forget((n, e, d));
            Ok(RsaPrivateKeyBuilder {
                rsa: Rsa::from_ptr(rsa),
            })
        }
    }

    /// Sets the factors of the Rsa key.
    ///
    /// `p` and `q` are the first and second factors of `n`.
    ///
    /// This correspond to [`RSA_set0_factors`].
    ///
    /// [`RSA_set0_factors`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_factors.html
    // FIXME should be infallible
    pub fn set_factors(self, p: BigNum, q: BigNum) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            RSA_set0_factors(self.rsa.as_ptr(), p.as_ptr(), q.as_ptr());
            mem::forget((p, q));
        }
        Ok(self)
    }

    /// Sets the Chinese Remainder Theorem params of the Rsa key.
    ///
    /// `dmp1`, `dmq1`, and `iqmp` are the exponents and coefficient for
    /// CRT calculations which is used to speed up RSA operations.
    ///
    /// This correspond to [`RSA_set0_crt_params`].
    ///
    /// [`RSA_set0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_crt_params.html
    // FIXME should be infallible
    pub fn set_crt_params(
        self,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    ) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            RSA_set0_crt_params(
                self.rsa.as_ptr(),
                dmp1.as_ptr(),
                dmq1.as_ptr(),
                iqmp.as_ptr(),
            );
            mem::forget((dmp1, dmq1, iqmp));
        }
        Ok(self)
    }

    /// Returns the Rsa key.
    pub fn build(self) -> Rsa<Private> {
        self.rsa
    }
}

impl Rsa<Private> {
    /// Creates a new RSA key with private components (public components are assumed).
    ///
    /// This a convenience method over
    /// `Rsa::build(n, e, d)?.set_factors(p, q)?.set_crt_params(dmp1, dmq1, iqmp)?.build()`
    pub fn from_private_components(
        n: BigNum,
        e: BigNum,
        d: BigNum,
        p: BigNum,
        q: BigNum,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    ) -> Result<Rsa<Private>, ErrorStack> {
        Ok(RsaPrivateKeyBuilder::new(n, e, d)?
            .set_factors(p, q)?
            .set_crt_params(dmp1, dmq1, iqmp)?
            .build())
    }

    /// Generates a public/private key pair with the specified size.
    ///
    /// The public exponent will be 65537.
    ///
    /// This corresponds to [`RSA_generate_key_ex`].
    ///
    /// [`RSA_generate_key_ex`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_generate_key_ex.html
    pub fn generate(bits: u32) -> Result<Rsa<Private>, ErrorStack> {
        let e = BigNum::from_u32(ffi::RSA_F4 as u32)?;
        Rsa::generate_with_e(bits, &e)
    }

    /// Generates a public/private key pair with the specified size and a custom exponent.
    ///
    /// Unless you have specific needs and know what you're doing, use `Rsa::generate` instead.
    ///
    /// This corresponds to [`RSA_generate_key_ex`].
    ///
    /// [`RSA_generate_key_ex`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_generate_key_ex.html
    pub fn generate_with_e(bits: u32, e: &BigNumRef) -> Result<Rsa<Private>, ErrorStack> {
        unsafe {
            let rsa = Rsa::from_ptr(cvt_p(ffi::RSA_new())?);
            cvt(ffi::RSA_generate_key_ex(
                rsa.0,
                bits as c_int,
                e.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(rsa)
        }
    }

    // FIXME these need to identify input formats
    private_key_from_pem! {
        /// Deserializes a private key from a PEM-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPrivateKey`].
        ///
        /// [`PEM_read_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_RSAPrivateKey.html
        private_key_from_pem,

        /// Deserializes a private key from a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPrivateKey`].
        ///
        /// [`PEM_read_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_RSAPrivateKey.html
        private_key_from_pem_passphrase,

        /// Deserializes a private key from a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// The callback should fill the password into the provided buffer and return its length.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPrivateKey`].
        ///
        /// [`PEM_read_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_RSAPrivateKey.html
        private_key_from_pem_callback,
        Rsa<Private>,
        ffi::PEM_read_bio_RSAPrivateKey
    }

    from_der! {
        /// Decodes a DER-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`d2i_RSAPrivateKey`].
        ///
        /// [`d2i_RSAPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_RSA_PUBKEY.html
        private_key_from_der,
        Rsa<Private>,
        ffi::d2i_RSAPrivateKey
    }
}

impl<T> fmt::Debug for Rsa<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rsa")
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl273))] {
        use ffi::{
            RSA_get0_key, RSA_get0_factors, RSA_get0_crt_params, RSA_set0_key, RSA_set0_factors,
            RSA_set0_crt_params,
        };
    } else {
        #[allow(bad_style)]
        unsafe fn RSA_get0_key(
            r: *const ffi::RSA,
            n: *mut *const ffi::BIGNUM,
            e: *mut *const ffi::BIGNUM,
            d: *mut *const ffi::BIGNUM,
        ) {
            if !n.is_null() {
                *n = (*r).n;
            }
            if !e.is_null() {
                *e = (*r).e;
            }
            if !d.is_null() {
                *d = (*r).d;
            }
        }

        #[allow(bad_style)]
        unsafe fn RSA_get0_factors(
            r: *const ffi::RSA,
            p: *mut *const ffi::BIGNUM,
            q: *mut *const ffi::BIGNUM,
        ) {
            if !p.is_null() {
                *p = (*r).p;
            }
            if !q.is_null() {
                *q = (*r).q;
            }
        }

        #[allow(bad_style)]
        unsafe fn RSA_get0_crt_params(
            r: *const ffi::RSA,
            dmp1: *mut *const ffi::BIGNUM,
            dmq1: *mut *const ffi::BIGNUM,
            iqmp: *mut *const ffi::BIGNUM,
        ) {
            if !dmp1.is_null() {
                *dmp1 = (*r).dmp1;
            }
            if !dmq1.is_null() {
                *dmq1 = (*r).dmq1;
            }
            if !iqmp.is_null() {
                *iqmp = (*r).iqmp;
            }
        }

        #[allow(bad_style)]
        unsafe fn RSA_set0_key(
            r: *mut ffi::RSA,
            n: *mut ffi::BIGNUM,
            e: *mut ffi::BIGNUM,
            d: *mut ffi::BIGNUM,
        ) -> c_int {
            (*r).n = n;
            (*r).e = e;
            (*r).d = d;
            1
        }

        #[allow(bad_style)]
        unsafe fn RSA_set0_factors(
            r: *mut ffi::RSA,
            p: *mut ffi::BIGNUM,
            q: *mut ffi::BIGNUM,
        ) -> c_int {
            (*r).p = p;
            (*r).q = q;
            1
        }

        #[allow(bad_style)]
        unsafe fn RSA_set0_crt_params(
            r: *mut ffi::RSA,
            dmp1: *mut ffi::BIGNUM,
            dmq1: *mut ffi::BIGNUM,
            iqmp: *mut ffi::BIGNUM,
        ) -> c_int {
            (*r).dmp1 = dmp1;
            (*r).dmq1 = dmq1;
            (*r).iqmp = iqmp;
            1
        }
    }
}

impl<T> Rsa<T> {
    pub fn new_ex_index<D>() -> Result<Index<Self, D>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            let idx = cvt_n(ffi::RSA_get_ex_new_index(
                0,
                ptr::null_mut(),
                None,
                None,
                Some(free_data_box::<D>),
            ))?;

            Ok(Index::from_raw(idx))
        }
    }
}

impl<T> RsaRef<T> {
    pub fn ex_data<D>(&self, idx: Index<Rsa<T>, D>) -> Option<&D> {
        unsafe { (ffi::RSA_get_ex_data(self.as_ptr(), idx.as_raw()) as *const D).as_ref() }
    }

    pub fn set_ex_data<D>(&mut self, index: Index<Rsa<T>, D>, data: D) -> Result<(), ErrorStack> {
        cvt(unsafe {
            let data = Box::new(data);

            ffi::RSA_set_ex_data(
                self.as_ptr(),
                index.as_raw(),
                Box::into_raw(data) as *mut c_void,
            )
        })
        .map(|_| ())
    }
}

bitflags! {
    pub struct Flags: c_int {
        /// don't check pub/private match
        const NO_CHECK = ffi::RSA_METHOD_FLAG_NO_CHECK as i32;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::RSA_METHOD;
    fn drop = RSA_meth_free;
    fn clone = RSA_meth_dup;

    /// A RSA methods.
    pub struct RsaMethod;

    /// Reference to `RsaMethod`
    pub struct RsaMethodRef;
}

impl RsaMethod {
    /// these are the actual RSA functions
    #[cfg(ossl110)]
    pub fn openssl() -> &'static RsaMethodRef {
        unsafe { RsaMethodRef::from_ptr(ffi::RSA_PKCS1_OpenSSL() as *mut _) }
    }

    /// these are the actual RSA functions
    #[cfg(not(ossl110))]
    pub fn openssl() -> &'static RsaMethodRef {
        unsafe { RsaMethodRef::from_ptr(ffi::RSA_PKCS1_SSLeay() as *mut _) }
    }

    pub fn default_method() -> Option<&'static RsaMethodRef> {
        let meth = unsafe { ffi::RSA_get_default_method() };

        if meth.is_null() {
            None
        } else {
            Some(unsafe { RsaMethodRef::from_ptr(meth as *mut _) })
        }
    }

    pub fn set_default_method(meth: Option<&RsaMethodRef>) {
        unsafe { ffi::RSA_set_default_method(meth.map_or_else(ptr::null_mut, |m| m.as_ptr())) }
    }

    pub fn new(name: &str) -> Self {
        Self::with_flags(name, Flags::empty())
    }

    pub fn with_flags(name: &str, flags: Flags) -> Self {
        unsafe {
            RsaMethod::from_ptr(RSA_meth_new(
                CString::new(name).unwrap().as_ptr(),
                flags.bits,
            ))
        }
    }
}

macro_rules! properties {
    ( $( pub $name:ident : $ty:ty { $getter:ident = $get:ident ; $setter:ident = $set:ident ; } )* ) => {
        $(
            #[cfg(any(ossl110, libressl280))]
            pub fn $getter(&self) -> $ty {
                unsafe { ffi::$get(self.as_ptr()) }
            }

            #[cfg(any(ossl110, libressl280))]
            pub fn $setter(&self, value: $ty) -> Result<(), ErrorStack> {
                cvt(unsafe { ffi::$set(self.as_ptr(), value) }).map(|_| ())
            }

            #[cfg(not(any(ossl110, libressl280)))]
            pub fn $getter(&self) -> $ty {
                unsafe { (*self.as_ptr()).$name }
            }

            #[cfg(not(any(ossl110, libressl280)))]
            pub fn $setter(&self, value: $ty) -> Result<(), ErrorStack> {
                unsafe { (*self.as_ptr()).$name = value }

                Ok(())
            }
        )*
    };
}

impl RsaMethodRef {
    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr(RSA_meth_get0_name(self.as_ptr())) }
    }

    pub fn set_name(&self, name: &str) -> Result<(), ErrorStack> {
        cvt(unsafe { RSA_meth_set1_name(self.as_ptr(), CString::new(name).unwrap().as_ptr()) })
            .map(|_| ())
    }

    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(unsafe { RSA_meth_get_flags(self.as_ptr()) })
    }

    pub fn set_flags(&self, flags: Flags) -> Result<(), ErrorStack> {
        cvt(unsafe { RSA_meth_set_flags(self.as_ptr(), flags.bits) }).map(|_| ())
    }

    pub fn app_data<T>(&self) -> Option<&T> {
        unsafe { (RSA_meth_get0_app_data(self.as_ptr()) as *const T).as_ref() }
    }

    pub fn set_app_data<T>(&self, data: Option<&mut T>) -> Result<(), ErrorStack> {
        cvt(unsafe {
            RSA_meth_set0_app_data(
                self.as_ptr(),
                data.map_or_else(ptr::null_mut, |v| &mut *v) as *mut _,
            )
        })
        .map(|_| ())
    }

    properties! {
        pub rsa_pub_enc: Option<
            unsafe extern "C" fn(
                flen: c_int,
                from: *const c_uchar,
                to: *mut c_uchar,
                rsa: *mut ffi::RSA,
                padding: c_int,
            ) -> c_int,
        > { pub_enc = RSA_meth_get_pub_enc; set_pub_enc = RSA_meth_set_pub_enc; }

        pub rsa_pub_dec: Option<
            unsafe extern "C" fn(
                flen: c_int,
                from: *const c_uchar,
                to: *mut c_uchar,
                rsa: *mut ffi::RSA,
                padding: c_int,
            ) -> c_int,
        > { pub_dec = RSA_meth_get_pub_dec; set_pub_dec = RSA_meth_set_pub_dec; }

        pub rsa_priv_enc: Option<
            unsafe extern "C" fn(
                flen: c_int,
                from: *const c_uchar,
                to: *mut c_uchar,
                rsa: *mut ffi::RSA,
                padding: c_int,
            ) -> c_int,
        > { priv_enc = RSA_meth_get_priv_enc; set_priv_enc = RSA_meth_set_priv_enc; }

        pub rsa_priv_dec: Option<
            unsafe extern "C" fn(
                flen: c_int,
                from: *const c_uchar,
                to: *mut c_uchar,
                rsa: *mut ffi::RSA,
                padding: c_int,
            ) -> c_int,
        > { priv_dec = RSA_meth_get_priv_dec; set_priv_dec = RSA_meth_set_priv_dec; }

        pub rsa_mod_exp: Option<
            unsafe extern "C" fn(
                r0: *mut ffi::BIGNUM,
                I: *const ffi::BIGNUM,
                rsa: *mut ffi::RSA,
                ctx: *mut ffi::BN_CTX,
            ) -> c_int,
        > { mod_exp = RSA_meth_get_mod_exp; set_mod_exp = RSA_meth_set_mod_exp; }

        pub bn_mod_exp: Option<
            unsafe extern "C" fn(
                r: *mut ffi::BIGNUM,
                a: *const ffi::BIGNUM,
                p: *const ffi::BIGNUM,
                m: *const ffi::BIGNUM,
                ctx: *mut ffi::BN_CTX,
                m_ctx: *mut ffi::BN_MONT_CTX,
            ) -> c_int,
        > { bn_mod_exp = RSA_meth_get_bn_mod_exp; set_bn_mod_exp = RSA_meth_set_bn_mod_exp; }

        pub init: Option<
            unsafe extern "C" fn(rsa: *mut ffi::RSA) -> c_int
        > { init = RSA_meth_get_init; set_init = RSA_meth_set_init; }

        pub finish: Option<
            unsafe extern "C" fn(rsa: *mut ffi::RSA) -> c_int
        > { finish = RSA_meth_get_finish; set_finish = RSA_meth_set_finish; }

        pub rsa_sign: Option<
            unsafe extern "C" fn(
                type_: c_int,
                m: *const c_uchar,
                m_length: c_uint,
                sigret: *mut c_uchar,
                siglen: *mut c_uint,
                rsa: *const ffi::RSA,
            ) -> c_int,
        > { sign = RSA_meth_get_sign; set_sign = RSA_meth_set_sign; }

        pub rsa_verify: Option<
            unsafe extern "C" fn(
                dtype: c_int,
                m: *const c_uchar,
                m_length: c_uint,
                sigbuf: *const c_uchar,
                siglen: c_uint,
                rsa: *const ffi::RSA,
            ) -> c_int,
        > { verify = RSA_meth_get_verify; set_verify = RSA_meth_set_verify; }

        pub rsa_keygen: Option<
            unsafe extern "C" fn(
                rsa: *mut ffi::RSA,
                bits: c_int,
                e: *mut ffi::BIGNUM,
                cb: *mut ffi::BN_GENCB,
            ) -> c_int,
        > { keygen = RSA_meth_get_keygen; set_keygen = RSA_meth_set_keygen; }
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        use ffi::{
            RSA_meth_dup, RSA_meth_free, RSA_meth_get0_app_data, RSA_meth_get0_name, RSA_meth_get_flags,
            RSA_meth_new, RSA_meth_set0_app_data, RSA_meth_set1_name, RSA_meth_set_flags,
        };
    } else {
        use libc::c_char;

        pub unsafe fn RSA_meth_new(name: *const c_char, flags: c_int) -> *mut ffi::RSA_METHOD {
            let ptr = OPENSSL_zalloc!(mem::size_of::<ffi::RSA_METHOD>()) as *mut ffi::RSA_METHOD;

            if let Some(meth) = ptr.as_mut() {
                meth.flags = flags;
                meth.name = OPENSSL_strdup!(name);

                if !meth.name.is_null() {
                    return ptr;
                }

                OPENSSL_free!(ptr)
            }

            RSAerr!(RSA_F_RSA_METH_NEW, ERR_R_MALLOC_FAILURE);

            ptr::null_mut()
        }

        pub unsafe fn RSA_meth_free(meth: *mut ffi::RSA_METHOD) {
            if !meth.is_null() {
                OPENSSL_free!((*meth).name);
                OPENSSL_free!(meth);
            }
        }

        pub unsafe fn RSA_meth_dup(meth: *const ffi::RSA_METHOD) -> *mut ffi::RSA_METHOD {
            let n = mem::size_of::<ffi::RSA_METHOD>();
            let ret = OPENSSL_malloc!(n) as *mut ffi::RSA_METHOD;

            if !ret.is_null() {
                libc::memcpy(ret as *mut _, meth as *mut _, n);

                (*ret).name = OPENSSL_strdup!((*meth).name);

                if !(*ret).name.is_null() {
                    return ret;
                }

                OPENSSL_free!(ret)
            }

            RSAerr!(RSA_F_RSA_METH_DUP, ERR_R_MALLOC_FAILURE);

            ptr::null_mut()
        }

        pub unsafe fn RSA_meth_get0_name(meth: *const ffi::RSA_METHOD) -> *const c_char {
            (*meth).name
        }

        pub unsafe fn RSA_meth_set1_name(meth: *mut ffi::RSA_METHOD, name: *const c_char) -> c_int {
            let name = OPENSSL_strdup!(name);

            if name.is_null() {
                RSAerr!(RSA_F_RSA_METH_SET1_NAME, ERR_R_MALLOC_FAILURE);

                0
            } else {
                OPENSSL_free!((*meth).name);
                (*meth).name = name;

                1
            }
        }

        pub unsafe fn RSA_meth_get_flags(meth: *const ffi::RSA_METHOD) -> c_int {
            (*meth).flags
        }

        pub unsafe fn RSA_meth_set_flags(meth: *mut ffi::RSA_METHOD, flags: c_int) -> c_int {
            (*meth).flags = flags;
            1
        }

        pub unsafe fn RSA_meth_get0_app_data(meth: *const ffi::RSA_METHOD) -> *mut c_void {
            (*meth).app_data as *mut _
        }

        pub unsafe fn RSA_meth_set0_app_data(
            meth: *mut ffi::RSA_METHOD,
            app_data: *mut c_void,
        ) -> c_int {
            (*meth).app_data = app_data as *mut _;
            1
        }
    }
}

#[cfg(test)]
mod test {
    use symm::Cipher;

    use super::*;

    #[test]
    fn test_from_password() {
        let key = include_bytes!("../test/rsa-encrypted.pem");
        Rsa::private_key_from_pem_passphrase(key, b"mypass").unwrap();
    }

    #[test]
    fn test_from_password_callback() {
        let mut password_queried = false;
        let key = include_bytes!("../test/rsa-encrypted.pem");
        Rsa::private_key_from_pem_callback(key, |password| {
            password_queried = true;
            password[..6].copy_from_slice(b"mypass");
            Ok(6)
        })
        .unwrap();

        assert!(password_queried);
    }

    #[test]
    fn test_to_password() {
        let key = Rsa::generate(2048).unwrap();
        let pem = key
            .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"foobar")
            .unwrap();
        Rsa::private_key_from_pem_passphrase(&pem, b"foobar").unwrap();
        assert!(Rsa::private_key_from_pem_passphrase(&pem, b"fizzbuzz").is_err());
    }

    #[test]
    fn test_public_encrypt_private_decrypt_with_padding() {
        let key = include_bytes!("../test/rsa.pem.pub");
        let public_key = Rsa::public_key_from_pem(key).unwrap();

        let mut result = vec![0; public_key.size() as usize];
        let original_data = b"This is test";
        let len = public_key
            .public_encrypt(original_data, &mut result, Padding::PKCS1)
            .unwrap();
        assert_eq!(len, 256);

        let pkey = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(pkey).unwrap();
        let mut dec_result = vec![0; private_key.size() as usize];
        let len = private_key
            .private_decrypt(&result, &mut dec_result, Padding::PKCS1)
            .unwrap();

        assert_eq!(&dec_result[..len], original_data);
    }

    #[test]
    fn test_private_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.public_key_to_pem().unwrap();
        let k1 = super::Rsa::public_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size() as usize];
        k0.private_encrypt(&msg, &mut emesg, Padding::PKCS1)
            .unwrap();
        let mut dmesg = vec![0; k1.size() as usize];
        let len = k1
            .public_decrypt(&emesg, &mut dmesg, Padding::PKCS1)
            .unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

    #[test]
    fn test_public_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.private_key_to_pem().unwrap();
        let k1 = super::Rsa::private_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size() as usize];
        k0.public_encrypt(&msg, &mut emesg, Padding::PKCS1).unwrap();
        let mut dmesg = vec![0; k1.size() as usize];
        let len = k1
            .private_decrypt(&emesg, &mut dmesg, Padding::PKCS1)
            .unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

    #[test]
    fn test_public_key_from_pem_pkcs1() {
        let key = include_bytes!("../test/pkcs1.pem.pub");
        Rsa::public_key_from_pem_pkcs1(key).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_public_key_from_pem_pkcs1_file_panic() {
        let key = include_bytes!("../test/key.pem.pub");
        Rsa::public_key_from_pem_pkcs1(key).unwrap();
    }

    #[test]
    fn test_public_key_to_pem_pkcs1() {
        let keypair = super::Rsa::generate(512).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_public_key_from_pem_pkcs1_generate_panic() {
        let keypair = super::Rsa::generate(512).unwrap();
        let pubkey_pem = keypair.public_key_to_pem().unwrap();
        super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
    }

    #[test]
    fn test_pem_pkcs1_encrypt() {
        let keypair = super::Rsa::generate(2048).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        let pubkey = super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
        let msg = "Hello, world!".as_bytes();

        let mut encrypted = vec![0; pubkey.size() as usize];
        let len = pubkey
            .public_encrypt(&msg, &mut encrypted, Padding::PKCS1)
            .unwrap();
        assert!(len > msg.len());
        let mut decrypted = vec![0; keypair.size() as usize];
        let len = keypair
            .private_decrypt(&encrypted, &mut decrypted, Padding::PKCS1)
            .unwrap();
        assert_eq!(len, msg.len());
        assert_eq!("Hello, world!", String::from_utf8_lossy(&decrypted[..len]));
    }

    #[test]
    fn test_pem_pkcs1_padding() {
        let keypair = super::Rsa::generate(2048).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        let pubkey = super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
        let msg = "foo".as_bytes();

        let mut encrypted1 = vec![0; pubkey.size() as usize];
        let mut encrypted2 = vec![0; pubkey.size() as usize];
        let len1 = pubkey
            .public_encrypt(&msg, &mut encrypted1, Padding::PKCS1)
            .unwrap();
        let len2 = pubkey
            .public_encrypt(&msg, &mut encrypted2, Padding::PKCS1)
            .unwrap();
        assert!(len1 > (msg.len() + 1));
        assert_eq!(len1, len2);
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn clone() {
        let key = Rsa::generate(2048).unwrap();
        drop(key.clone());
    }

    #[test]
    fn generate_with_e() {
        let e = BigNum::from_u32(0x10001).unwrap();
        Rsa::generate_with_e(2048, &e).unwrap();
    }
}
