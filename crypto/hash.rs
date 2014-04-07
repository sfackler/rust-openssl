use libc;
use libc::c_uint;
use std::ptr;
use std::slice;

pub enum HashType {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
}

#[allow(non_camel_case_types)]
pub type EVP_MD_CTX = *libc::c_void;

#[allow(non_camel_case_types)]
pub type EVP_MD = *libc::c_void;

#[link(name = "crypto")]
extern {
    fn EVP_MD_CTX_create() -> EVP_MD_CTX;
    fn EVP_MD_CTX_destroy(ctx: EVP_MD_CTX);

    fn EVP_md5() -> EVP_MD;
    fn EVP_sha1() -> EVP_MD;
    fn EVP_sha224() -> EVP_MD;
    fn EVP_sha256() -> EVP_MD;
    fn EVP_sha384() -> EVP_MD;
    fn EVP_sha512() -> EVP_MD;

    fn EVP_DigestInit(ctx: EVP_MD_CTX, typ: EVP_MD);
    fn EVP_DigestUpdate(ctx: EVP_MD_CTX, data: *u8, n: c_uint);
    fn EVP_DigestFinal(ctx: EVP_MD_CTX, res: *mut u8, n: *u32);
}

pub fn evpmd(t: HashType) -> (EVP_MD, uint) {
    unsafe {
        match t {
            MD5 => (EVP_md5(), 16u),
            SHA1 => (EVP_sha1(), 20u),
            SHA224 => (EVP_sha224(), 28u),
            SHA256 => (EVP_sha256(), 32u),
            SHA384 => (EVP_sha384(), 48u),
            SHA512 => (EVP_sha512(), 64u),
        }
    }
}

pub struct Hasher {
    evp: EVP_MD,
    ctx: EVP_MD_CTX,
    len: uint,
}

impl Hasher {
    pub fn new(ht: HashType) -> Hasher {
        let ctx = unsafe { EVP_MD_CTX_create() };
        let (evp, mdlen) = evpmd(ht);
        unsafe {
            EVP_DigestInit(ctx, evp);
        }

        Hasher { evp: evp, ctx: ctx, len: mdlen }
    }

    /// Update this hasher with more input bytes
    pub fn update(&self, data: &[u8]) {
        unsafe {
            EVP_DigestUpdate(self.ctx, data.as_ptr(), data.len() as c_uint)
        }
    }

    /**
     * Return the digest of all bytes added to this hasher since its last
     * initialization
     */
    pub fn final(&self) -> ~[u8] {
        unsafe {
            let mut res = slice::from_elem(self.len, 0u8);
            EVP_DigestFinal(self.ctx, res.as_mut_ptr(), ptr::null());
            res
        }
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_destroy(self.ctx);
        }
    }
}

/**
 * Hashes the supplied input data using hash t, returning the resulting hash
 * value
 */
pub fn hash(t: HashType, data: &[u8]) -> ~[u8] {
    let h = Hasher::new(t);
    h.update(data);
    h.final()
}

#[cfg(test)]
mod tests {
    use serialize::hex::{FromHex, ToHex};

    struct HashTest {
        input: ~[u8],
        expected_output: ~str
    }

    fn HashTest(input: ~str, output: ~str) -> HashTest {
        HashTest { input: input.from_hex().unwrap(),
                   expected_output: output }
    }

    fn hash_test(hashtype: super::HashType, hashtest: &HashTest) {
        let calced_raw = super::hash(hashtype, hashtest.input);

        let calced = calced_raw.to_hex();

        if calced != hashtest.expected_output {
            println!("Test failed - {} != {}", calced, hashtest.expected_output);
        }

        assert!(calced == hashtest.expected_output);
    }

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[test]
    fn test_md5() {
        let tests = [
            HashTest(~"", ~"d41d8cd98f00b204e9800998ecf8427e"),
            HashTest(~"7F", ~"83acb6e67e50e31db6ed341dd2de1595"),
            HashTest(~"EC9C", ~"0b07f0d4ca797d8ac58874f887cb0b68"),
            HashTest(~"FEE57A", ~"e0d583171eb06d56198fc0ef22173907"),
            HashTest(~"42F497E0", ~"7c430f178aefdf1487fee7144e9641e2"),
            HashTest(~"C53B777F1C", ~"75ef141d64cb37ec423da2d9d440c925"),
            HashTest(~"89D5B576327B", ~"ebbaf15eb0ed784c6faa9dc32831bf33"),
            HashTest(~"5D4CCE781EB190", ~"ce175c4b08172019f05e6b5279889f2c"),
            HashTest(~"81901FE94932D7B9", ~"cd4d2f62b8cdb3a0cf968a735a239281"),
            HashTest(~"C9FFDEE7788EFB4EC9", ~"e0841a231ab698db30c6c0f3f246c014"),
            HashTest(~"66AC4B7EBA95E53DC10B", ~"a3b3cea71910d9af56742aa0bb2fe329"),
            HashTest(~"A510CD18F7A56852EB0319", ~"577e216843dd11573574d3fb209b97d8"),
            HashTest(~"AAED18DBE8938C19ED734A8D", ~"6f80fb775f27e0a4ce5c2f42fc72c5f1")];

        for test in tests.iter() {
            hash_test(super::MD5, test);
        }
    }

    #[test]
    fn test_sha1() {
        let tests = [
            HashTest(~"616263", ~"a9993e364706816aba3e25717850c26c9cd0d89d"),
            ];

        for test in tests.iter() {
            hash_test(super::SHA1, test);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = [
            HashTest(~"616263", ~"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            ];

        for test in tests.iter() {
            hash_test(super::SHA256, test);
        }
    }
}
