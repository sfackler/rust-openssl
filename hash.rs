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

fn evpmd(t: HashType) -> (EVP_MD, uint) {
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

pub fn Hasher(ht: HashType) -> Hasher {
    let ctx = unsafe { libcrypto::EVP_MD_CTX_create() };
    let (evp, mdlen) = evpmd(ht);
    let h = Hasher { evp: evp, ctx: ctx, len: mdlen };
    h.init();
    h
}

impl Hasher {
    /// Initializes this hasher
    pub fn init(&self) {
        unsafe { libcrypto::EVP_DigestInit(self.ctx, self.evp) }
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

/**
 * Hashes the supplied input data using hash t, returning the resulting hash
 * value
 */
pub fn hash(t: HashType, data: &[u8]) -> ~[u8] {
    let h = Hasher(t);
    h.update(data);
    h.final()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[test]
    fn test_md5() {
        let s0 = ~[0x61u8, 0x62u8, 0x63u8];
        let d0 = 
           ~[0x90u8, 0x01u8, 0x50u8, 0x98u8, 0x3cu8, 0xd2u8, 0x4fu8, 0xb0u8,
             0xd6u8, 0x96u8, 0x3fu8, 0x7du8, 0x28u8, 0xe1u8, 0x7fu8, 0x72u8];
        assert!(hash(MD5, s0) == d0);
    }

    #[test]
    fn test_sha1() {
        let s0 = ~[0x61u8, 0x62u8, 0x63u8];
        let d0 =
           ~[0xa9u8, 0x99u8, 0x3eu8, 0x36u8, 0x47u8, 0x06u8, 0x81u8, 0x6au8,
             0xbau8, 0x3eu8, 0x25u8, 0x71u8, 0x78u8, 0x50u8, 0xc2u8, 0x6cu8,
             0x9cu8, 0xd0u8, 0xd8u8, 0x9du8];
        assert!(hash(SHA1, s0) == d0);
    }

    #[test]
    fn test_sha256() {
        let s0 = ~[0x61u8, 0x62u8, 0x63u8];
        let d0 =
           ~[0xbau8, 0x78u8, 0x16u8, 0xbfu8, 0x8fu8, 0x01u8, 0xcfu8, 0xeau8,
             0x41u8, 0x41u8, 0x40u8, 0xdeu8, 0x5du8, 0xaeu8, 0x22u8, 0x23u8,
             0xb0u8, 0x03u8, 0x61u8, 0xa3u8, 0x96u8, 0x17u8, 0x7au8, 0x9cu8,
             0xb4u8, 0x10u8, 0xffu8, 0x61u8, 0xf2u8, 0x00u8, 0x15u8, 0xadu8];
        assert!(hash(SHA256, s0) == d0);
    }
}
