use std::libc::c_uint;
use std::libc;
use std::ptr;
use std::vec;

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

mod libcrypto {
    use super::*;
    use std::libc::c_uint;

    #[link_args = "-lcrypto"]
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
}

pub fn evpmd(t: HashType) -> (EVP_MD, uint) {
    unsafe {
        match t {
            MD5 => (libcrypto::EVP_md5(), 16u),
            SHA1 => (libcrypto::EVP_sha1(), 20u),
            SHA224 => (libcrypto::EVP_sha224(), 28u),
            SHA256 => (libcrypto::EVP_sha256(), 32u),
            SHA384 => (libcrypto::EVP_sha384(), 48u),
            SHA512 => (libcrypto::EVP_sha512(), 64u),
        }
    }
}

pub struct Hasher {
    priv evp: EVP_MD,
    priv ctx: EVP_MD_CTX,
    priv len: uint,
}

impl Hasher {
    pub fn new(ht: HashType) -> Hasher {
        let ctx = unsafe { libcrypto::EVP_MD_CTX_create() };
        let (evp, mdlen) = evpmd(ht);
        unsafe {
            libcrypto::EVP_DigestInit(ctx, evp);
        }

        Hasher { evp: evp, ctx: ctx, len: mdlen }
    }

    /// Update this hasher with more input bytes
    pub fn update(&self, data: &[u8]) {
        do data.as_imm_buf |pdata, len| {
            unsafe {
                libcrypto::EVP_DigestUpdate(self.ctx, pdata, len as c_uint)
            }
        }
    }

    /**
     * Return the digest of all bytes added to this hasher since its last
     * initialization
     */
    pub fn final(&self) -> ~[u8] {
        let mut res = vec::from_elem(self.len, 0u8);
        do res.as_mut_buf |pres, _len| {
            unsafe {
                libcrypto::EVP_DigestFinal(self.ctx, pres, ptr::null());
            }
        }
        res
    }
}

impl Drop for Hasher {
    fn drop(&self) {
        unsafe {
            libcrypto::EVP_MD_CTX_destroy(self.ctx);
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
    use super::*;
    use hex::FromHex;
    use hex::ToHex;

    struct HashTest {
        input: ~[u8],
        expected_output: ~str
    }

    fn HashTest(input: ~str, output: ~str) -> HashTest {
        HashTest { input: input.from_hex(),
                   expected_output: output }
    }

    fn hash_test(hashtype: HashType, hashtest: &HashTest) {
        let calced_raw = hash(hashtype, hashtest.input);

        let calced = calced_raw.to_hex();

        if calced != hashtest.expected_output {
            println(fmt!("Test failed - %s != %s", calced, hashtest.expected_output));
        }

        assert!(calced == hashtest.expected_output);
    }

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[test]
    fn test_md5() {
        let tests = [
            HashTest(~"", ~"D41D8CD98F00B204E9800998ECF8427E"),
            HashTest(~"7F", ~"83ACB6E67E50E31DB6ED341DD2DE1595"),
            HashTest(~"EC9C", ~"0B07F0D4CA797D8AC58874F887CB0B68"),
            HashTest(~"FEE57A", ~"E0D583171EB06D56198FC0EF22173907"),
            HashTest(~"42F497E0", ~"7C430F178AEFDF1487FEE7144E9641E2"),
            HashTest(~"C53B777F1C", ~"75EF141D64CB37EC423DA2D9D440C925"),
            HashTest(~"89D5B576327B", ~"EBBAF15EB0ED784C6FAA9DC32831BF33"),
            HashTest(~"5D4CCE781EB190", ~"CE175C4B08172019F05E6B5279889F2C"),
            HashTest(~"81901FE94932D7B9", ~"CD4D2F62B8CDB3A0CF968A735A239281"),
            HashTest(~"C9FFDEE7788EFB4EC9", ~"E0841A231AB698DB30C6C0F3F246C014"),
            HashTest(~"66AC4B7EBA95E53DC10B", ~"A3B3CEA71910D9AF56742AA0BB2FE329"),
            HashTest(~"A510CD18F7A56852EB0319", ~"577E216843DD11573574D3FB209B97D8"),
            HashTest(~"AAED18DBE8938C19ED734A8D", ~"6F80FB775F27E0A4CE5C2F42FC72C5F1")];

        for test in tests.iter() {
            hash_test(MD5, test);
        }
    }

    #[test]
    fn test_sha1() {
        let tests = [
            HashTest(~"616263", ~"A9993E364706816ABA3E25717850C26C9CD0D89D"),
            ];

        for test in tests.iter() {
            hash_test(SHA1, test);
        }
    }

    #[test]
    fn test_sha256() {
        let tests = [
            HashTest(~"616263", ~"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
            ];

        for test in tests.iter() {
            hash_test(SHA256, test);
        }
    }
}
