//! An abstract interface over various specific cryptographic hash algorithms.
//!
//! The `Hasher` type can be configured to hash bytes with any of a variety of supported hash
//! algorithms. It is particularly useful in cases where you need to work with any type
//! that supports a hashing interface. Furthermore, `Hasher` implements the [std::io::Write](
//! https://doc.rust-lang.org/std/io/trait.Write.html) trait.
//! # Examples
//!
//! ```rust
//! extern crate openssl;
//! extern crate hex;
//!
//! use std::io;
//! use std::io::Write;
//! use openssl::hash;
//! use hex::ToHex;
//!
//! fn main() {
//!     let mut hasher = hash::Hasher::new(hash::MessageDigest::sha512()).unwrap();
//!     let bytes_hashed = hash_stream(&mut hasher).unwrap();
//!     let hash = hasher.finish2().unwrap();
//!     println!("Hashed {} bytes to {}", bytes_hashed, hash.to_hex());
//! }
//!
//! fn hash_stream<W: Write>(hasher: &mut W) -> io::Result<usize> {
//!     let mut total_bytes = 0;
//!
//!     total_bytes += hasher.write(b"HTTP/1.1 200 OK\r\n")?;
//!     total_bytes += hasher.write(b"Content-Length: 5\r\n")?;
//!     total_bytes += hasher.write(b"\r\n\r\n")?;
//!     total_bytes += hasher.write(b"hello")?;
//!
//!     Ok(total_bytes)
//! }
//! ```
use std::io::prelude::*;
use std::io;
use std::ops::{Deref, DerefMut};
use std::fmt;
use ffi;

#[cfg(ossl110)]
use ffi::{EVP_MD_CTX_new, EVP_MD_CTX_free};
#[cfg(any(ossl101, ossl102))]
use ffi::{EVP_MD_CTX_create as EVP_MD_CTX_new, EVP_MD_CTX_destroy as EVP_MD_CTX_free};

use {cvt, cvt_p};
use error::ErrorStack;

#[derive(Copy, Clone)]
pub struct MessageDigest(*const ffi::EVP_MD);

impl MessageDigest {
    /// Construct a `MessageDigest` that will hash bytes supplied to `Hasher.update` using the MD5
    /// hash algorithm.
    ///
    /// # Warning
    ///
    /// MD5 is no longer considered secure, and should only be used for compatibility with legacy
    /// systems.
    pub fn md5() -> MessageDigest {
        unsafe { MessageDigest(ffi::EVP_md5()) }
    }

    /// Construct a `MessageDigest` that will hash bytes supplied to `Hasher.update` using the SHA1
    /// hash algorithm.
    ///
    /// # Warning
    ///
    /// SHA1 is no longer considered secure for use in new software.  Its use should be limited to
    /// cases where compatibility with legacy systems is required.
    pub fn sha1() -> MessageDigest {
        unsafe { MessageDigest(ffi::EVP_sha1()) }
    }

    /// Construct a `MessageDigest` that will hash bytes supplied to `Hasher.update` using the
    /// SHA-224 hash algorithm.
    pub fn sha224() -> MessageDigest {
        unsafe { MessageDigest(ffi::EVP_sha224()) }
    }

    /// Construct a `MessageDigest` that will hash bytes supplied to `Hasher.update` using the
    /// SHA-256 hash algorithm.
    pub fn sha256() -> MessageDigest {
        unsafe { MessageDigest(ffi::EVP_sha256()) }
    }

    /// Construct a `MessageDigest` that will hash bytes supplied to `Hasher.update` using the
    /// SHA-384 hash algorithm.
    pub fn sha384() -> MessageDigest {
        unsafe { MessageDigest(ffi::EVP_sha384()) }
    }

    /// Construct a `MessageDigest` that will hash bytes supplied to `Hasher.update` using the
    /// SHA-512 hash algorithm.
    pub fn sha512() -> MessageDigest {
        unsafe { MessageDigest(ffi::EVP_sha512()) }
    }

    /// Construct a `MessageDigest` that will hash bytes supplied to `Hasher.update` using the
    /// RIPEMD-160 hash algorithm.
    pub fn ripemd160() -> MessageDigest {
        unsafe { MessageDigest(ffi::EVP_ripemd160()) }
    }

    /// Obtains a pointer to the underlying identifier for the message digest algorithm in use.
    pub fn as_ptr(&self) -> *const ffi::EVP_MD {
        self.0
    }
}

/// Represents the state of a message digest, which moves through three states as it is created,
/// updated with new bytes to hash, and finalized as a way of completing a hashing operation.
#[derive(PartialEq, Copy, Clone)]
enum State {
    Reset,
    Updated,
    Finalized,
}

use self::State::*;

/// Provides message digest (hash) computation.
///
/// # Examples
///
/// Calculate a hash in one go:
///
/// ```
/// use openssl::hash::{hash, MessageDigest};
///
/// let data = b"\x42\xF4\x97\xE0";
/// let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
/// let res = hash(MessageDigest::md5(), data).unwrap();
/// assert_eq!(res, spec);
/// ```
///
/// Supply the input in chunks:
///
/// ```
/// use openssl::hash::{Hasher, MessageDigest};
///
/// let data = [b"\x42\xF4", b"\x97\xE0"];
/// let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
/// let mut h = Hasher::new(MessageDigest::md5()).unwrap();
/// h.update(data[0]).unwrap();
/// h.update(data[1]).unwrap();
/// let res = h.finish().unwrap();
/// assert_eq!(res, spec);
/// ```
///
/// # Warning
///
/// The MD5 and SHA-1 hash algorithms are no longer considered secure and should not be used in new
/// software. Use of these algorithms should be restricted only to cases where compatibility with
/// legacy systems is required.
///
/// The hash algorithms available here are not suited to password hashing. For such applications,
/// prefer instead to use either the `pkcs5` module or, more simply, either bcrypt or scrypt.
pub struct Hasher {
    ctx: *mut ffi::EVP_MD_CTX,
    md: *const ffi::EVP_MD,
    type_: MessageDigest,
    state: State,
}

impl Hasher {
    /// Creates a new `Hasher` with the specified hash type.  The `MessageDigest` provided
    /// ultimately determines which algorithm is used to hash bytes supplied to the `update`
    /// method.
    pub fn new(ty: MessageDigest) -> Result<Hasher, ErrorStack> {
        ffi::init();

        let ctx = unsafe { cvt_p(EVP_MD_CTX_new())? };

        let mut h = Hasher {
            ctx: ctx,
            md: ty.as_ptr(),
            type_: ty,
            state: Finalized,
        };
        h.init()?;
        Ok(h)
    }

    /// Initialize the `Hasher` so that it enters a state wherein bytes can be supplied to the
    /// `update` method as if the `Hasher` had just been created.  Note that if the `Hasher` had
    /// already been updated before, any work done will be lost.
    fn init(&mut self) -> Result<(), ErrorStack> {
        match self.state {
            Reset => return Ok(()),
            Updated => {
                self.finish2()?;
            }
            Finalized => (),
        }
        unsafe {
            cvt(ffi::EVP_DigestInit_ex(self.ctx, self.md, 0 as *mut _))?;
        }
        self.state = Reset;
        Ok(())
    }

    /// Add bytes for hashing. This method can be called multiple times with the effect being that
    /// the `Hasher` will hash all of the bytes supplied via `update` as if the slices in each call
    /// were part of one larger slice with the second concatenated at the end of the first.
    pub fn update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        if self.state == Finalized {
            self.init()?;
        }
        unsafe {
            cvt(ffi::EVP_DigestUpdate(
                self.ctx,
                data.as_ptr() as *mut _,
                data.len(),
            ))?;
        }
        self.state = Updated;
        Ok(())
    }

    #[deprecated(note = "use finish2 instead", since = "0.9.11")]
    pub fn finish(&mut self) -> Result<Vec<u8>, ErrorStack> {
        self.finish2().map(|b| b.to_vec())
    }

    /// Returns the hash of the data written and resets the hasher.
    ///
    /// Unlike `finish`, this method does not allocate.
    pub fn finish2(&mut self) -> Result<DigestBytes, ErrorStack> {
        if self.state == Finalized {
            self.init()?;
        }
        unsafe {
            let mut len = ffi::EVP_MAX_MD_SIZE;
            let mut buf = [0; ffi::EVP_MAX_MD_SIZE as usize];
            cvt(ffi::EVP_DigestFinal_ex(
                self.ctx,
                buf.as_mut_ptr(),
                &mut len,
            ))?;
            self.state = Finalized;
            Ok(DigestBytes {
                buf: buf,
                len: len as usize,
            })
        }
    }
}

impl Write for Hasher {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Clone for Hasher {
    fn clone(&self) -> Hasher {
        let ctx = unsafe {
            let ctx = EVP_MD_CTX_new();
            assert!(!ctx.is_null());
            let r = ffi::EVP_MD_CTX_copy_ex(ctx, self.ctx);
            assert_eq!(r, 1);
            ctx
        };
        Hasher {
            ctx: ctx,
            md: self.md,
            type_: self.type_,
            state: self.state,
        }
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        unsafe {
            if self.state != Finalized {
                drop(self.finish2());
            }
            EVP_MD_CTX_free(self.ctx);
        }
    }
}

/// The resulting bytes of a digest.
///
/// This type derefs to a byte slice - it exists to avoid allocating memory to
/// store the digest data.
#[derive(Copy)]
pub struct DigestBytes {
    buf: [u8; ffi::EVP_MAX_MD_SIZE as usize],
    len: usize,
}

impl Clone for DigestBytes {
    #[inline]
    fn clone(&self) -> DigestBytes {
        *self
    }
}

impl Deref for DigestBytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl DerefMut for DigestBytes {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl AsRef<[u8]> for DigestBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl fmt::Debug for DigestBytes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}

#[deprecated(note = "use hash2 instead", since = "0.9.11")]
pub fn hash(t: MessageDigest, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    hash2(t, data).map(|b| b.to_vec())
}

/// Computes the hash of the `data` with the hash `t`.
///
/// Unlike `hash`, this function does not allocate the return value.
pub fn hash2(t: MessageDigest, data: &[u8]) -> Result<DigestBytes, ErrorStack> {
    let mut h = Hasher::new(t)?;
    h.update(data)?;
    h.finish2()
}

#[cfg(test)]
mod tests {
    use hex::{FromHex, ToHex};
    use std::io::prelude::*;

    use super::*;

    fn hash_test(hashtype: MessageDigest, hashtest: &(&str, &str)) {
        let res = hash2(hashtype, &Vec::from_hex(hashtest.0).unwrap()).unwrap();
        assert_eq!(res.to_hex(), hashtest.1);
    }

    fn hash_recycle_test(h: &mut Hasher, hashtest: &(&str, &str)) {
        let _ = h.write_all(&Vec::from_hex(hashtest.0).unwrap()).unwrap();
        let res = h.finish2().unwrap();
        assert_eq!(res.to_hex(), hashtest.1);
    }

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[allow(non_upper_case_globals)]
    const md5_tests: [(&'static str, &'static str); 13] =
        [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("7F", "83acb6e67e50e31db6ed341dd2de1595"),
            ("EC9C", "0b07f0d4ca797d8ac58874f887cb0b68"),
            ("FEE57A", "e0d583171eb06d56198fc0ef22173907"),
            ("42F497E0", "7c430f178aefdf1487fee7144e9641e2"),
            ("C53B777F1C", "75ef141d64cb37ec423da2d9d440c925"),
            ("89D5B576327B", "ebbaf15eb0ed784c6faa9dc32831bf33"),
            ("5D4CCE781EB190", "ce175c4b08172019f05e6b5279889f2c"),
            ("81901FE94932D7B9", "cd4d2f62b8cdb3a0cf968a735a239281"),
            ("C9FFDEE7788EFB4EC9", "e0841a231ab698db30c6c0f3f246c014"),
            ("66AC4B7EBA95E53DC10B", "a3b3cea71910d9af56742aa0bb2fe329"),
            ("A510CD18F7A56852EB0319", "577e216843dd11573574d3fb209b97d8"),
            (
                "AAED18DBE8938C19ED734A8D",
                "6f80fb775f27e0a4ce5c2f42fc72c5f1",
            ),
        ];

    #[test]
    fn test_md5() {
        for test in md5_tests.iter() {
            hash_test(MessageDigest::md5(), test);
        }
    }

    #[test]
    fn test_md5_recycle() {
        let mut h = Hasher::new(MessageDigest::md5()).unwrap();
        for test in md5_tests.iter() {
            hash_recycle_test(&mut h, test);
        }
    }

    #[test]
    fn test_finish_twice() {
        let mut h = Hasher::new(MessageDigest::md5()).unwrap();
        h.write_all(&Vec::from_hex(md5_tests[6].0).unwrap())
            .unwrap();
        h.finish2().unwrap();
        let res = h.finish2().unwrap();
        let null = hash2(MessageDigest::md5(), &[]).unwrap();
        assert_eq!(&*res, &*null);
    }

    #[test]
    fn test_clone() {
        let i = 7;
        let inp = Vec::from_hex(md5_tests[i].0).unwrap();
        assert!(inp.len() > 2);
        let p = inp.len() / 2;
        let h0 = Hasher::new(MessageDigest::md5()).unwrap();

        println!("Clone a new hasher");
        let mut h1 = h0.clone();
        h1.write_all(&inp[..p]).unwrap();
        {
            println!("Clone an updated hasher");
            let mut h2 = h1.clone();
            h2.write_all(&inp[p..]).unwrap();
            let res = h2.finish2().unwrap();
            assert_eq!(res.to_hex(), md5_tests[i].1);
        }
        h1.write_all(&inp[p..]).unwrap();
        let res = h1.finish2().unwrap();
        assert_eq!(res.to_hex(), md5_tests[i].1);

        println!("Clone a finished hasher");
        let mut h3 = h1.clone();
        h3.write_all(&Vec::from_hex(md5_tests[i + 1].0).unwrap())
            .unwrap();
        let res = h3.finish2().unwrap();
        assert_eq!(res.to_hex(), md5_tests[i + 1].1);
    }

    #[test]
    fn test_sha1() {
        let tests = [("616263", "a9993e364706816aba3e25717850c26c9cd0d89d")];

        for test in tests.iter() {
            hash_test(MessageDigest::sha1(), test);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = [
            (
                "616263",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ];

        for test in tests.iter() {
            hash_test(MessageDigest::sha256(), test);
        }
    }

    #[test]
    fn test_ripemd160() {
        let tests = [("616263", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")];

        for test in tests.iter() {
            hash_test(MessageDigest::ripemd160(), test);
        }
    }
}
