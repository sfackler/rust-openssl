use std;

import core::ptr;
import core::str;
import core::vec;

import libc::c_int;

export crypter;
export cryptermode;
export encryptmode, decryptmode;
export cryptertype;
export aes_256_ecb, aes_256_cbc;
export mk_crypter;
export encrypt, decrypt;
export _native;

type EVP_CIPHER_CTX = *libc::c_void;
type EVP_CIPHER = *libc::c_void;

#[link_name = "crypto"]
#[abi = "cdecl"]
native mod _native {
    fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_set_padding(ctx: EVP_CIPHER_CTX, padding: c_int);

    fn EVP_aes_128_ecb() -> EVP_CIPHER;
    fn EVP_aes_128_cbc() -> EVP_CIPHER;
    fn EVP_aes_192_ecb() -> EVP_CIPHER;
    fn EVP_aes_192_cbc() -> EVP_CIPHER;
    fn EVP_aes_256_ecb() -> EVP_CIPHER;
    fn EVP_aes_256_cbc() -> EVP_CIPHER;

    fn EVP_CipherInit(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER,
                       key: *u8, iv: *u8, mode: c_int);
    fn EVP_CipherUpdate(ctx: EVP_CIPHER_CTX, outbuf: *u8, outlen: *u32,
                         inbuf: *u8, inlen: u32);
    fn EVP_CipherFinal(ctx: EVP_CIPHER_CTX, res: *u8, len: *u32);
}

/*
Object: crypter

Represents a symmetric cipher context.
*/
iface crypter {
    /*
    Method: pad

    Enables or disables padding. If padding is disabled, total amount of data
    encrypted must be a multiple of block size.
    */
    fn pad(padding: bool);

    /*
    Method: init

    Initializes this crypter.
    */
    fn init(mode: cryptermode, key: [u8], iv: [u8]);

    /*
    Method: update

    Update this crypter with more data to encrypt or decrypt. Returns encrypted
    or decrypted bytes.
    */
    fn update(data: [u8]) -> [u8];

    /*
    Method: final

    Finish crypting. Returns the remaining partial block of output, if any.
    */
    fn final() -> [u8];
}

enum cryptermode {
    encryptmode,
    decryptmode
}

enum cryptertype {
    aes_256_ecb,
    aes_256_cbc
}

fn evpc(t: cryptertype) -> (EVP_CIPHER, uint, uint) {
    alt t {
        aes_256_ecb { (_native::EVP_aes_256_ecb(), 32u, 16u) }
        aes_256_cbc { (_native::EVP_aes_256_cbc(), 32u, 16u) }
    }
}

fn mk_crypter(t: cryptertype) -> crypter {
    type crypterstate = {
        evp: EVP_CIPHER,
        ctx: EVP_CIPHER_CTX,
        keylen: uint,
        blocksize: uint
    };

    impl of crypter for crypterstate {
        fn pad(padding: bool) {
            let v = if padding { 1 } else { 0} as c_int;
            _native::EVP_CIPHER_CTX_set_padding(self.ctx, v);
        }

        fn init (mode: cryptermode, key: [u8], iv: [u8]) unsafe {
            let m = alt mode { encryptmode { 1 } decryptmode { 0 } } as c_int;
            assert(vec::len(key) == self.keylen);
            let pkey: *u8 = vec::unsafe::to_ptr::<u8>(key);
            let piv: *u8 = vec::unsafe::to_ptr::<u8>(iv);
            _native::EVP_CipherInit(self.ctx, self.evp, pkey, piv, m);
        }

        fn update(data: [u8]) -> [u8] unsafe {
            let pdata: *u8 = vec::unsafe::to_ptr::<u8>(data);
            let datalen: u32 = vec::len(data) as u32;
            let reslen: u32 = datalen + (self.blocksize as u32);
            let preslen: *u32 = ptr::addr_of(reslen);
            let res: [mut u8] = vec::to_mut(vec::from_elem::<u8>(reslen as uint, 0u8));
            let pres: *u8 = vec::unsafe::to_ptr::<u8>(res);
            _native::EVP_CipherUpdate(self.ctx, pres, preslen, pdata, datalen);
            ret vec::slice::<u8>(res, 0u, *preslen as uint);
        }

        fn final() -> [u8] unsafe {
            let reslen: u32 = self.blocksize as u32;
            let preslen: *u32 = ptr::addr_of(reslen);
            let res: [mut u8] = vec::to_mut(vec::from_elem::<u8>(reslen as uint, 0u8));
            let pres: *u8 = vec::unsafe::to_ptr::<u8>(res);
            _native::EVP_CipherFinal(self.ctx, pres, preslen);
            ret vec::slice::<u8>(res, 0u, *preslen as uint);
        }
    }

    let ctx = _native::EVP_CIPHER_CTX_new();
    let (evp, keylen, blocksz) = evpc(t);
    let st = { evp: evp, ctx: ctx, keylen: keylen, blocksize: blocksz };
    let h = st as crypter;
    ret h;
}

/*
Function: encrypt

Encrypts data, using the specified crypter type in encrypt mode with the
specified key and iv; returns the resulting (encrypted) data.
*/
fn encrypt(t: cryptertype, key: [u8], iv: [u8], data: [u8]) -> [u8] {
    let c = mk_crypter(t);
    c.init(encryptmode, key, iv);
    let r = c.update(data);
    let rest = c.final();
    ret r + rest;
}

/*
Function: decrypt

Decrypts data, using the specified crypter type in decrypt mode with the
specified key and iv; returns the resulting (decrypted) data.
*/
fn decrypt(t: cryptertype, key: [u8], iv: [u8], data: [u8]) -> [u8] {
    let c = mk_crypter(t);
    c.init(decryptmode, key, iv);
    let r = c.update(data);
    let rest = c.final();
    ret r + rest;
}

#[cfg(test)]
mod tests {
    // Test vectors from FIPS-197:
    // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    #[test]
    fn test_aes_256_ecb() {
        let k0 =
            [ 0x00u8, 0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8,
              0x08u8, 0x09u8, 0x0au8, 0x0bu8, 0x0cu8, 0x0du8, 0x0eu8, 0x0fu8,
              0x10u8, 0x11u8, 0x12u8, 0x13u8, 0x14u8, 0x15u8, 0x16u8, 0x17u8,
              0x18u8, 0x19u8, 0x1au8, 0x1bu8, 0x1cu8, 0x1du8, 0x1eu8, 0x1fu8 ];
        let p0 =
            [ 0x00u8, 0x11u8, 0x22u8, 0x33u8, 0x44u8, 0x55u8, 0x66u8, 0x77u8,
              0x88u8, 0x99u8, 0xaau8, 0xbbu8, 0xccu8, 0xddu8, 0xeeu8, 0xffu8 ];
        let c0 =
            [ 0x8eu8, 0xa2u8, 0xb7u8, 0xcau8, 0x51u8, 0x67u8, 0x45u8, 0xbfu8,
              0xeau8, 0xfcu8, 0x49u8, 0x90u8, 0x4bu8, 0x49u8, 0x60u8, 0x89u8 ];
        let c = mk_crypter(aes_256_ecb);
        c.init(encryptmode, k0, []);
        c.pad(false);
        let r0 = c.update(p0) + c.final();
        assert(r0 == c0);
        c.init(decryptmode, k0, []);
        c.pad(false);
        let p1 = c.update(r0) + c.final();
        assert(p1 == p0);
    }
}
