use std;

import core::ptr;
import core::str;
import core::vec;

import libc::c_uint;

export hasher;
export hashtype;
export mk_hasher;
export hash;
export _native;

export md5, sha1, sha224, sha256, sha384, sha512;

iface hasher {
    /*
    Method: init

    Initializes this hasher
    */
    fn init();

    /*
    Method: update

    Update this hasher with more input bytes
    */
    fn update([u8]);

    /*
    Method: final

    Return the digest of all bytes added to this hasher since its last
    initialization
    */
    fn final() -> [u8];
}

enum hashtype {
    md5,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512
}

type EVP_MD_CTX = *libc::c_void;
type EVP_MD = *libc::c_void;

#[link_name = "crypto"]
#[abi = "cdecl"]
native mod _native {
    fn EVP_MD_CTX_create() -> EVP_MD_CTX;

    fn EVP_md5() -> EVP_MD;
    fn EVP_sha1() -> EVP_MD;
    fn EVP_sha224() -> EVP_MD;
    fn EVP_sha256() -> EVP_MD;
    fn EVP_sha384() -> EVP_MD;
    fn EVP_sha512() -> EVP_MD;

    fn EVP_DigestInit(ctx: EVP_MD_CTX, typ: EVP_MD);
    fn EVP_DigestUpdate(ctx: EVP_MD_CTX, data: *u8, n: c_uint);
    fn EVP_DigestFinal(ctx: EVP_MD_CTX, res: *u8, n: *u32);
}

fn evpmd(t: hashtype) -> (EVP_MD, uint) {
    alt t {
        md5 { (_native::EVP_md5(), 16u) }
        sha1 { (_native::EVP_sha1(), 20u) }
        sha224 { (_native::EVP_sha224(), 28u) }
        sha256 { (_native::EVP_sha256(), 32u) }
        sha384 { (_native::EVP_sha384(), 48u) }
        sha512 { (_native::EVP_sha512(), 64u) }
    }
}

fn mk_hasher(ht: hashtype) -> hasher {
    type hasherstate = {
        evp: EVP_MD,
        ctx: EVP_MD_CTX,
        len: uint
    };

    impl of hasher for hasherstate {
        fn init() unsafe {
            _native::EVP_DigestInit(self.ctx, self.evp);
        }

        fn update(data: [u8]) unsafe {
            let pdata: *u8 = vec::unsafe::to_ptr::<u8>(data);
            _native::EVP_DigestUpdate(self.ctx, pdata, vec::len(data) as c_uint);
        }

        fn final() -> [u8] unsafe {
            let res: [mut u8] = vec::to_mut(vec::from_elem::<u8>(self.len, 0u8));
            let pres: *u8 = vec::unsafe::to_ptr::<u8>(res);
            _native::EVP_DigestFinal(self.ctx, pres, ptr::null::<u32>());
            vec::from_mut::<u8>(res)
        }
    }

    let ctx = _native::EVP_MD_CTX_create();
    let (evp, mdlen) = evpmd(ht);
    let st = { evp: evp, ctx: ctx, len: mdlen };
    let h = st as hasher;
    h.init();
    ret h;
}

/*
Function: hash

Hashes the supplied input data using hash t, returning the resulting hash value
*/
fn hash(t: hashtype, data: [u8]) -> [u8] unsafe {
    let h = mk_hasher(t);
    h.init();
    h.update(data);
    ret h.final();
}

#[cfg(test)]
mod tests {
    // Test vectors from http://www.nsrl.nist.gov/testdata/
    #[test]
    fn test_md5() {
        let s0 = [0x61u8, 0x62u8, 0x63u8];
        let d0 = 
            [0x90u8, 0x01u8, 0x50u8, 0x98u8, 0x3cu8, 0xd2u8, 0x4fu8, 0xb0u8,
             0xd6u8, 0x96u8, 0x3fu8, 0x7du8, 0x28u8, 0xe1u8, 0x7fu8, 0x72u8];
        assert(hash(md5, s0) == d0);
    }

    #[test]
    fn test_sha1() {
        let s0 = [0x61u8, 0x62u8, 0x63u8];
        let d0 =
            [0xa9u8, 0x99u8, 0x3eu8, 0x36u8, 0x47u8, 0x06u8, 0x81u8, 0x6au8,
             0xbau8, 0x3eu8, 0x25u8, 0x71u8, 0x78u8, 0x50u8, 0xc2u8, 0x6cu8,
             0x9cu8, 0xd0u8, 0xd8u8, 0x9du8];
        assert(hash(sha1, s0) == d0);
    }

    #[test]
    fn test_sha256() {
        let s0 = [0x61u8, 0x62u8, 0x63u8];
        let d0 =
            [0xbau8, 0x78u8, 0x16u8, 0xbfu8, 0x8fu8, 0x01u8, 0xcfu8, 0xeau8,
             0x41u8, 0x41u8, 0x40u8, 0xdeu8, 0x5du8, 0xaeu8, 0x22u8, 0x23u8,
             0xb0u8, 0x03u8, 0x61u8, 0xa3u8, 0x96u8, 0x17u8, 0x7au8, 0x9cu8,
             0xb4u8, 0x10u8, 0xffu8, 0x61u8, 0xf2u8, 0x00u8, 0x15u8, 0xadu8];
        assert(hash(sha256, s0) == d0);
    }
}
