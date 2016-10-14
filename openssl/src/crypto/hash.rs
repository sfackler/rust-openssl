use std::io::prelude::*;
use std::io;
use std::ptr;
use ffi;

use HashTypeInternals;
use error::ErrorStack;
use nid::Nid;

/// Message digest (hash) type.
#[derive(Copy, Clone)]
pub enum Type {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    RIPEMD160,
}

impl HashTypeInternals for Type {
    fn as_nid(&self) -> Nid {
        match *self {
            Type::MD5 => Nid::MD5,
            Type::SHA1 => Nid::SHA1,
            Type::SHA224 => Nid::SHA224,
            Type::SHA256 => Nid::SHA256,
            Type::SHA384 => Nid::SHA384,
            Type::SHA512 => Nid::SHA512,
            Type::RIPEMD160 => Nid::RIPEMD160,
        }
    }

    fn evp_md(&self) -> *const ffi::EVP_MD {
        unsafe {
            match *self {
                Type::MD5 => ffi::EVP_md5(),
                Type::SHA1 => ffi::EVP_sha1(),
                Type::SHA224 => ffi::EVP_sha224(),
                Type::SHA256 => ffi::EVP_sha256(),
                Type::SHA384 => ffi::EVP_sha384(),
                Type::SHA512 => ffi::EVP_sha512(),
                Type::RIPEMD160 => ffi::EVP_ripemd160(),
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
/// let res = hash(Type::MD5, data).unwrap();
/// assert_eq!(res, spec);
/// ```
///
/// Use the `Write` trait to supply the input in chunks.
///
/// ```
/// use openssl::crypto::hash::{Hasher, Type};
/// let data = [b"\x42\xF4", b"\x97\xE0"];
/// let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
/// let mut h = Hasher::new(Type::MD5).unwrap();
/// h.update(data[0]).unwrap();
/// h.update(data[1]).unwrap();
/// let res = h.finish().unwrap();
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
    pub fn new(ty: Type) -> Result<Hasher, ErrorStack> {
        ffi::init();

        let ctx = unsafe { try_ssl_null!(ffi::EVP_MD_CTX_new()) };
        let md = ty.evp_md();

        let mut h = Hasher {
            ctx: ctx,
            md: md,
            type_: ty,
            state: Finalized,
        };
        try!(h.init());
        Ok(h)
    }

    fn init(&mut self) -> Result<(), ErrorStack> {
        match self.state {
            Reset => return Ok(()),
            Updated => {
                try!(self.finish());
            }
            Finalized => (),
        }
        unsafe { try_ssl!(ffi::EVP_DigestInit_ex(self.ctx, self.md, 0 as *mut _)); }
        self.state = Reset;
        Ok(())
    }

    /// Feeds data into the hasher.
    pub fn update(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        if self.state == Finalized {
            try!(self.init());
        }
        unsafe {
            try_ssl!(ffi::EVP_DigestUpdate(self.ctx,
                                           data.as_ptr() as *mut _,
                                           data.len()));
        }
        self.state = Updated;
        Ok(())
    }

    /// Returns the hash of the data written since creation or
    /// the last `finish` and resets the hasher.
    pub fn finish(&mut self) -> Result<Vec<u8>, ErrorStack> {
        if self.state == Finalized {
            try!(self.init());
        }
        unsafe {
            let mut len = ffi::EVP_MAX_MD_SIZE;
            let mut res = vec![0; len as usize];
            try_ssl!(ffi::EVP_DigestFinal_ex(self.ctx, res.as_mut_ptr(), &mut len));
            res.truncate(len as usize);
            self.state = Finalized;
            Ok(res)
        }
    }
}

impl Write for Hasher {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try!(self.update(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Clone for Hasher {
    fn clone(&self) -> Hasher {
        let ctx = unsafe {
            let ctx = ffi::EVP_MD_CTX_new();
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
                drop(self.finish());
            }
            ffi::EVP_MD_CTX_free(self.ctx);
        }
    }
}

/// Computes the hash of the `data` with the hash `t`.
pub fn hash(t: Type, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut h = try!(Hasher::new(t));
    try!(h.update(data));
    h.finish()
}

#[cfg(test)]
mod tests {
    use serialize::hex::{FromHex, ToHex};
    use super::{hash, Hasher, Type};
    use std::io::prelude::*;

    fn hash_test(hashtype: Type, hashtest: &(&str, &str)) {
        let res = hash(hashtype, &*hashtest.0.from_hex().unwrap()).unwrap();
        assert_eq!(res.to_hex(), hashtest.1);
    }

    fn hash_recycle_test(h: &mut Hasher, hashtest: &(&str, &str)) {
        let _ = h.write_all(&*hashtest.0.from_hex().unwrap()).unwrap();
        let res = h.finish().unwrap();
        assert_eq!(res.to_hex(), hashtest.1);
    }

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[allow(non_upper_case_globals)]
    const md5_tests: [(&'static str, &'static str); 13] = [("",
                                                            "d41d8cd98f00b204e9800998ecf8427e"),
                                                           ("7F",
                                                            "83acb6e67e50e31db6ed341dd2de1595"),
                                                           ("EC9C",
                                                            "0b07f0d4ca797d8ac58874f887cb0b68"),
                                                           ("FEE57A",
                                                            "e0d583171eb06d56198fc0ef22173907"),
                                                           ("42F497E0",
                                                            "7c430f178aefdf1487fee7144e9641e2"),
                                                           ("C53B777F1C",
                                                            "75ef141d64cb37ec423da2d9d440c925"),
                                                           ("89D5B576327B",
                                                            "ebbaf15eb0ed784c6faa9dc32831bf33"),
                                                           ("5D4CCE781EB190",
                                                            "ce175c4b08172019f05e6b5279889f2c"),
                                                           ("81901FE94932D7B9",
                                                            "cd4d2f62b8cdb3a0cf968a735a239281"),
                                                           ("C9FFDEE7788EFB4EC9",
                                                            "e0841a231ab698db30c6c0f3f246c014"),
                                                           ("66AC4B7EBA95E53DC10B",
                                                            "a3b3cea71910d9af56742aa0bb2fe329"),
                                                           ("A510CD18F7A56852EB0319",
                                                            "577e216843dd11573574d3fb209b97d8"),
                                                           ("AAED18DBE8938C19ED734A8D",
                                                            "6f80fb775f27e0a4ce5c2f42fc72c5f1")];

    #[test]
    fn test_md5() {
        for test in md5_tests.iter() {
            hash_test(Type::MD5, test);
        }
    }

    #[test]
    fn test_md5_recycle() {
        let mut h = Hasher::new(Type::MD5).unwrap();
        for test in md5_tests.iter() {
            hash_recycle_test(&mut h, test);
        }
    }

    #[test]
    fn test_finish_twice() {
        let mut h = Hasher::new(Type::MD5).unwrap();
        h.write_all(&*md5_tests[6].0.from_hex().unwrap()).unwrap();
        h.finish().unwrap();
        let res = h.finish().unwrap();
        let null = hash(Type::MD5, &[]).unwrap();
        assert_eq!(res, null);
    }

    #[test]
    fn test_clone() {
        let i = 7;
        let inp = md5_tests[i].0.from_hex().unwrap();
        assert!(inp.len() > 2);
        let p = inp.len() / 2;
        let h0 = Hasher::new(Type::MD5).unwrap();

        println!("Clone a new hasher");
        let mut h1 = h0.clone();
        h1.write_all(&inp[..p]).unwrap();
        {
            println!("Clone an updated hasher");
            let mut h2 = h1.clone();
            h2.write_all(&inp[p..]).unwrap();
            let res = h2.finish().unwrap();
            assert_eq!(res.to_hex(), md5_tests[i].1);
        }
        h1.write_all(&inp[p..]).unwrap();
        let res = h1.finish().unwrap();
        assert_eq!(res.to_hex(), md5_tests[i].1);

        println!("Clone a finished hasher");
        let mut h3 = h1.clone();
        h3.write_all(&*md5_tests[i + 1].0.from_hex().unwrap()).unwrap();
        let res = h3.finish().unwrap();
        assert_eq!(res.to_hex(), md5_tests[i + 1].1);
    }

    #[test]
    fn test_sha1() {
        let tests = [("616263", "a9993e364706816aba3e25717850c26c9cd0d89d")];

        for test in tests.iter() {
            hash_test(Type::SHA1, test);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = [("616263",
                      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")];

        for test in tests.iter() {
            hash_test(Type::SHA256, test);
        }
    }

    #[test]
    fn test_ripemd160() {
        let tests = [("616263", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")];

        for test in tests.iter() {
            hash_test(Type::RIPEMD160, test);
        }
    }
}
