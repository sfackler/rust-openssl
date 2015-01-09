use libc::c_uint;
use std::ptr;
use std::io;
use std::iter::repeat;

use ffi;

#[derive(Copy)]
pub enum HashType {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    RIPEMD160
}

pub fn evpmd(t: HashType) -> (*const ffi::EVP_MD, u32) {
    unsafe {
        match t {
            HashType::MD5 => (ffi::EVP_md5(), 16),
            HashType::SHA1 => (ffi::EVP_sha1(), 20),
            HashType::SHA224 => (ffi::EVP_sha224(), 28),
            HashType::SHA256 => (ffi::EVP_sha256(), 32),
            HashType::SHA384 => (ffi::EVP_sha384(), 48),
            HashType::SHA512 => (ffi::EVP_sha512(), 64),
            HashType::RIPEMD160 => (ffi::EVP_ripemd160(), 20),
        }
    }
}

pub struct HasherContext {
    ptr: *mut ffi::EVP_MD_CTX
}

impl HasherContext {
    pub fn new() -> HasherContext {
        ffi::init();

        unsafe {
            HasherContext { ptr: ffi::EVP_MD_CTX_create() }
        }
    }
}

impl Drop for HasherContext {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_MD_CTX_destroy(self.ptr);
        }
    }
}

#[allow(dead_code)]
pub struct Hasher {
    evp: *const ffi::EVP_MD,
    ctx: HasherContext,
    len: u32,
}

impl io::Writer for Hasher {
    fn write(&mut self, buf: &[u8]) -> io::IoResult<()> {
        self.update(buf);
        Ok(())
    }
}

impl Hasher {
    pub fn new(ht: HashType) -> Hasher {
        let ctx = HasherContext::new();
        Hasher::with_context(ctx, ht)
    }

    pub fn with_context(ctx: HasherContext, ht: HashType) -> Hasher {
        let (evp, mdlen) = evpmd(ht);
        unsafe {
            ffi::EVP_DigestInit_ex(ctx.ptr, evp, 0 as *const _);
        }

        Hasher { evp: evp, ctx: ctx, len: mdlen }
    }

    /// Update this hasher with more input bytes
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            ffi::EVP_DigestUpdate(self.ctx.ptr, data.as_ptr(), data.len() as c_uint)
        }
    }

    /**
     * Return the digest of all bytes added to this hasher since its last
     * initialization
     */
    pub fn finalize(self) -> Vec<u8> {
        let (res, _) = self.finalize_reuse();
        res
    }

    /**
     * Return the digest of all bytes added to this hasher since its last
     * initialization and its context for reuse
     */
    pub fn finalize_reuse(self) -> (Vec<u8>, HasherContext) {
        let mut res = repeat(0u8).take(self.len as usize).collect::<Vec<_>>();
        unsafe {
            ffi::EVP_DigestFinal_ex(self.ctx.ptr, res.as_mut_ptr(), ptr::null_mut())
        };
        (res, self.ctx)
    }
}

/**
 * Hashes the supplied input data using hash t, returning the resulting hash
 * value
 */
pub fn hash(t: HashType, data: &[u8]) -> Vec<u8> {
    let mut h = Hasher::new(t);
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use serialize::hex::{FromHex, ToHex};

    struct HashTest {
        input: Vec<u8>,
        expected_output: String
    }

    #[allow(non_snake_case)]
    fn HashTest(input: &str, output: &str) -> HashTest {
        HashTest { input: input.from_hex().unwrap(),
                   expected_output: output.to_string() }
    }

    fn compare(calced_raw: Vec<u8>, hashtest: &HashTest) {
        let calced = calced_raw.as_slice().to_hex().to_string();

        if calced != hashtest.expected_output {
            println!("Test failed - {} != {}", calced, hashtest.expected_output);
        }

        assert!(calced == hashtest.expected_output);
    }

    fn hash_test(hashtype: super::HashType, hashtest: &HashTest) {
        let calced_raw = super::hash(hashtype, hashtest.input.as_slice());
        compare(calced_raw, hashtest);
    }

    fn hash_reuse_test(ctx: super::HasherContext, hashtype: super::HashType,
                       hashtest: &HashTest) -> super::HasherContext {
        let mut h = super::Hasher::with_context(ctx, hashtype);
        h.update(hashtest.input.as_slice());
        let (calced_raw, ctx) = h.finalize_reuse();

        compare(calced_raw, hashtest);

        ctx
    }

    pub fn hash_writer(t: super::HashType, data: &[u8]) -> Vec<u8> {
        let mut h = super::Hasher::new(t);
        h.write(data).unwrap();
        h.finalize()
    }

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[test]
    fn test_md5() {
        let tests = [
            HashTest("", "d41d8cd98f00b204e9800998ecf8427e"),
            HashTest("7F", "83acb6e67e50e31db6ed341dd2de1595"),
            HashTest("EC9C", "0b07f0d4ca797d8ac58874f887cb0b68"),
            HashTest("FEE57A", "e0d583171eb06d56198fc0ef22173907"),
            HashTest("42F497E0", "7c430f178aefdf1487fee7144e9641e2"),
            HashTest("C53B777F1C", "75ef141d64cb37ec423da2d9d440c925"),
            HashTest("89D5B576327B", "ebbaf15eb0ed784c6faa9dc32831bf33"),
            HashTest("5D4CCE781EB190", "ce175c4b08172019f05e6b5279889f2c"),
            HashTest("81901FE94932D7B9", "cd4d2f62b8cdb3a0cf968a735a239281"),
            HashTest("C9FFDEE7788EFB4EC9", "e0841a231ab698db30c6c0f3f246c014"),
            HashTest("66AC4B7EBA95E53DC10B", "a3b3cea71910d9af56742aa0bb2fe329"),
            HashTest("A510CD18F7A56852EB0319", "577e216843dd11573574d3fb209b97d8"),
            HashTest("AAED18DBE8938C19ED734A8D", "6f80fb775f27e0a4ce5c2f42fc72c5f1")];

        let mut ctx = super::HasherContext::new();

        for test in tests.iter() {
            ctx = hash_reuse_test(ctx, super::HashType::MD5, test);
        }
    }

    #[test]
    fn test_sha1() {
        let tests = [
            HashTest("616263", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ];

        for test in tests.iter() {
            hash_test(super::HashType::SHA1, test);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = [
            HashTest("616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            ];

        for test in tests.iter() {
            hash_test(super::HashType::SHA256, test);
        }
    }

    #[test]
    fn test_ripemd160() {
        let tests = [
            HashTest("616263", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
            ];

        for test in tests.iter() {
            hash_test(super::HashType::RIPEMD160, test);
        }
    }

    #[test]
    fn test_writer() {
        let tv = "rust-openssl".as_bytes();
        let ht = super::HashType::RIPEMD160;
        assert!(hash_writer(ht, tv) == super::hash(ht, tv));
    }
}
