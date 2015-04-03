use libc::c_uint;
use std::iter::repeat;
use std::io::prelude::*;
use std::io;

use ffi;

/// Message digest (hash) type.
#[derive(Copy, Clone)]
pub enum Type {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    RIPEMD160
}

impl Type {
    /// Returns the length of the message digest.
    #[inline]
    pub fn md_len(&self) -> usize {
        use self::Type::*;
        match *self {
            MD5 => 16,
            SHA1 => 20,
            SHA224 => 28,
            SHA256 => 32,
            SHA384 => 48,
            SHA512 => 64,
            RIPEMD160 => 20,
        }
    }

    /// Internal interface subject to removal.
    #[inline]
    pub fn evp_md(&self) -> *const ffi::EVP_MD {
        unsafe {
            use self::Type::*;
            match *self {
                MD5 => ffi::EVP_md5(),
                SHA1 => ffi::EVP_sha1(),
                SHA224 => ffi::EVP_sha224(),
                SHA256 => ffi::EVP_sha256(),
                SHA384 => ffi::EVP_sha384(),
                SHA512 => ffi::EVP_sha512(),
                RIPEMD160 => ffi::EVP_ripemd160(),
            }
        }
    }
}

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
/// Calculate a hash in one go.
///
/// ```
/// use openssl::crypto::hash::{hash, Type};
/// let data = b"\x42\xF4\x97\xE0";
/// let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
/// let res = hash(Type::MD5, data);
/// assert_eq!(res, spec);
/// ```
///
/// Use the `Write` trait to supply the input in chunks.
///
/// ```
/// use std::io::prelude::*;
/// use openssl::crypto::hash::{Hasher, Type};
/// let data = [b"\x42\xF4", b"\x97\xE0"];
/// let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
/// let mut h = Hasher::new(Type::MD5);
/// h.write_all(data[0]);
/// h.write_all(data[1]);
/// let res = h.finish();
/// assert_eq!(res, spec);
/// ```
///
/// # Warning
///
/// Don't actually use MD5 and SHA-1 hashes, they're not secure anymore.
///
/// Don't ever hash passwords, use `crypto::pkcs5` or bcrypt/scrypt instead.
pub struct Hasher {
    ctx: *mut ffi::EVP_MD_CTX,
    md: *const ffi::EVP_MD,
    type_: Type,
    state: State,
}

impl Hasher {
    /// Creates a new `Hasher` with the specified hash type.
    pub fn new(ty: Type) -> Hasher {
        ffi::init();

        let ctx = unsafe {
            let r = ffi::EVP_MD_CTX_create();
            assert!(!r.is_null());
            r
        };
        let md = ty.evp_md();

        let mut h = Hasher { ctx: ctx, md: md, type_: ty, state: Finalized };
        h.init();
        h
    }

    #[inline]
    fn init(&mut self) {
        match self.state {
            Reset => return,
            Updated => { self.finalize(); },
            Finalized => (),
        }
        unsafe {
            let r = ffi::EVP_DigestInit_ex(self.ctx, self.md, 0 as *const _);
            assert_eq!(r, 1);
        }
        self.state = Reset;
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        if self.state == Finalized {
            self.init();
        }
        unsafe {
            let r = ffi::EVP_DigestUpdate(self.ctx, data.as_ptr(),
                                          data.len() as c_uint);
            assert_eq!(r, 1);
        }
        self.state = Updated;
    }

    #[inline]
    fn finalize(&mut self) -> Vec<u8> {
        if self.state == Finalized {
            self.init();
        }
        let md_len = self.type_.md_len();
        let mut res: Vec<u8> = repeat(0).take(md_len).collect();
        unsafe {
            let mut len = 0;
            let r = ffi::EVP_DigestFinal_ex(self.ctx, res.as_mut_ptr(), &mut len);
            self.state = Finalized;
            assert_eq!(len as usize, md_len);
            assert_eq!(r, 1);
        }
        res
    }

    /// Returns the hash of the data written since creation or
    /// the last `finish` and resets the hasher.
    #[inline]
    pub fn finish(&mut self) -> Vec<u8> {
        self.finalize()
    }
}

impl Write for Hasher {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Clone for Hasher {
    fn clone(&self) -> Hasher {
        let ctx = unsafe {
            let ctx = ffi::EVP_MD_CTX_create();
            assert!(!ctx.is_null());
            let r = ffi::EVP_MD_CTX_copy_ex(ctx, self.ctx);
            assert_eq!(r, 1);
            ctx
        };
        Hasher { ctx: ctx, md: self.md, type_: self.type_, state: self.state }
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        unsafe {
            if self.state != Finalized {
                let mut buf: Vec<u8> = repeat(0).take(self.type_.md_len()).collect();
                let mut len = 0;
                ffi::EVP_DigestFinal_ex(self.ctx, buf.as_mut_ptr(), &mut len);
            }
            ffi::EVP_MD_CTX_destroy(self.ctx);
        }
    }
}

/// Computes the hash of the `data` with the hash `t`.
pub fn hash(t: Type, data: &[u8]) -> Vec<u8> {
    let mut h = Hasher::new(t);
    let _ = h.write_all(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use serialize::hex::{FromHex, ToHex};
    use super::{hash, Hasher, Type};
    use std::io::prelude::*;

    fn hash_test(hashtype: Type, hashtest: &(&str, &str)) {
        let res = hash(hashtype, &*hashtest.0.from_hex().unwrap());
        assert_eq!(res.to_hex(), hashtest.1);
    }

    fn hash_recycle_test(h: &mut Hasher, hashtest: &(&str, &str)) {
        let _ = h.write_all(&*hashtest.0.from_hex().unwrap());
        let res = h.finish();
        assert_eq!(res.to_hex(), hashtest.1);
    }

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[allow(non_upper_case_globals)]
    const md5_tests: [(&'static str, &'static str); 13] = [
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
        ("AAED18DBE8938C19ED734A8D", "6f80fb775f27e0a4ce5c2f42fc72c5f1")
    ];

    #[test]
    fn test_md5() {
        for test in md5_tests.iter() {
            hash_test(Type::MD5, test);
        }
    }

    #[test]
    fn test_md5_recycle() {
        let mut h = Hasher::new(Type::MD5);
        for test in md5_tests.iter() {
            hash_recycle_test(&mut h, test);
        }
    }

    #[test]
    fn test_finish_twice() {
        let mut h = Hasher::new(Type::MD5);
        let _ = h.write_all(&*md5_tests[6].0.from_hex().unwrap());
        let _ = h.finish();
        let res = h.finish();
        let null = hash(Type::MD5, &[]);
        assert_eq!(res, null);
    }

    #[test]
    fn test_clone() {
        let i = 7;
        let inp = md5_tests[i].0.from_hex().unwrap();
        assert!(inp.len() > 2);
        let p = inp.len() / 2;
        let h0 = Hasher::new(Type::MD5);

        println!("Clone a new hasher");
        let mut h1 = h0.clone();
        let _ = h1.write_all(&inp[..p]);
        {
            println!("Clone an updated hasher");
            let mut h2 = h1.clone();
            let _ = h2.write_all(&inp[p..]);
            let res = h2.finish();
            assert_eq!(res.to_hex(), md5_tests[i].1);
        }
        let _ = h1.write_all(&inp[p..]);
        let res = h1.finish();
        assert_eq!(res.to_hex(), md5_tests[i].1);

        println!("Clone a finished hasher");
        let mut h3 = h1.clone();
        let _ = h3.write_all(&*md5_tests[i + 1].0.from_hex().unwrap());
        let res = h3.finish();
        assert_eq!(res.to_hex(), md5_tests[i + 1].1);
    }

    #[test]
    fn test_sha1() {
        let tests = [
            ("616263", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ];

        for test in tests.iter() {
            hash_test(Type::SHA1, test);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = [
            ("616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            ];

        for test in tests.iter() {
            hash_test(Type::SHA256, test);
        }
    }

    #[test]
    fn test_ripemd160() {
        let tests = [
            ("616263", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
            ];

        for test in tests.iter() {
            hash_test(Type::RIPEMD160, test);
        }
    }
}
