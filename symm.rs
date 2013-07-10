use std::libc::{c_int, c_uint};
use std::{libc,vec};

#[allow(non_camel_case_types)]
type EVP_CIPHER_CTX = *libc::c_void;

#[allow(non_camel_case_types)]
type EVP_CIPHER = *libc::c_void;

#[link_args = "-lcrypto"]
#[abi = "cdecl"]
extern {
    fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_set_padding(ctx: EVP_CIPHER_CTX, padding: c_int);

    fn EVP_aes_128_ecb() -> EVP_CIPHER;
    fn EVP_aes_128_cbc() -> EVP_CIPHER;
    // fn EVP_aes_128_ctr() -> EVP_CIPHER;
    // fn EVP_aes_128_gcm() -> EVP_CIPHER;

    fn EVP_aes_256_ecb() -> EVP_CIPHER;
    fn EVP_aes_256_cbc() -> EVP_CIPHER;
    // fn EVP_aes_256_ctr() -> EVP_CIPHER;
    // fn EVP_aes_256_gcm() -> EVP_CIPHER;

    fn EVP_rc4() -> EVP_CIPHER;

    fn EVP_CipherInit(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER,
                    key: *u8, iv: *u8, mode: c_int);
    fn EVP_CipherUpdate(ctx: EVP_CIPHER_CTX, outbuf: *mut u8,
                        outlen: &mut c_uint, inbuf: *u8, inlen: c_int);
    fn EVP_CipherFinal(ctx: EVP_CIPHER_CTX, res: *mut u8, len: &mut c_int);
}

pub enum Mode {
    Encrypt,
    Decrypt,
}

#[allow(non_camel_case_types)]
pub enum Type {
    AES_128_ECB,
    AES_128_CBC,
    // AES_128_CTR,
    //AES_128_GCM,

    AES_256_ECB,
    AES_256_CBC,
    // AES_256_CTR,
    //AES_256_GCM,

    RC4_128,
}

fn evpc(t: Type) -> (EVP_CIPHER, uint, uint) {
    unsafe {
        match t {
            AES_128_ECB => (EVP_aes_128_ecb(), 16u, 16u),
            AES_128_CBC => (EVP_aes_128_cbc(), 16u, 16u),
            // AES_128_CTR => (EVP_aes_128_ctr(), 16u, 0u),
            //AES_128_GCM => (EVP_aes_128_gcm(), 16u, 16u),

            AES_256_ECB => (EVP_aes_256_ecb(), 32u, 16u),
            AES_256_CBC => (EVP_aes_256_cbc(), 32u, 16u),
            // AES_256_CTR => (EVP_aes_256_ctr(), 32u, 0u),
            //AES_256_GCM => (EVP_aes_256_gcm(), 32u, 16u),

            RC4_128 => (EVP_rc4(), 16u, 0u),
        }
    }
}

/// Represents a symmetric cipher context.
pub struct Crypter {
    priv evp: EVP_CIPHER,
    priv ctx: EVP_CIPHER_CTX,
    priv keylen: uint,
    priv blocksize: uint
}

pub fn Crypter(t: Type) -> Crypter {
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        let (evp, keylen, blocksz) = evpc(t);
        Crypter { evp: evp, ctx: ctx, keylen: keylen, blocksize: blocksz }
    }
}

impl Crypter {
    /**
     * Enables or disables padding. If padding is disabled, total amount of
     * data encrypted must be a multiple of block size.
     */
    pub fn pad(&self, padding: bool) {
        if self.blocksize > 0 {
            unsafe {
                let v = if padding { 1 } else { 0 } as c_int;
                EVP_CIPHER_CTX_set_padding(self.ctx, v);
            }
        }
    }

    /**
     * Initializes this crypter.
     */
    pub fn init(&self, mode: Mode, key: &[u8], iv: &[u8]) {
        unsafe {
            let mode = match mode {
                Encrypt => 1 as c_int,
                Decrypt => 0 as c_int,
            };
            assert!(key.len() == self.keylen);

            do key.as_imm_buf |pkey, _len| {
                do iv.as_imm_buf |piv, _len| {
                    EVP_CipherInit(
                        self.ctx,
                        self.evp,
                        pkey,
                        piv,
                        mode
                    )
                }
            }
        }
    }

    /**
     * Update this crypter with more data to encrypt or decrypt. Returns
     * encrypted or decrypted bytes.
     */
    pub fn update(&self, data: &[u8]) -> ~[u8] {
        unsafe {
            do data.as_imm_buf |pdata, len| {
                let mut res = vec::from_elem(len + self.blocksize, 0u8);

                let reslen = do res.as_mut_buf |pres, _len| {
                    let mut reslen = (len + self.blocksize) as u32;

                    EVP_CipherUpdate(
                        self.ctx,
                        pres,
                        &mut reslen,
                        pdata,
                        len as c_int
                    );

                    reslen
                };

                res.slice(0u, reslen as uint).to_owned()
            }
        }
    }

    /**
     * Finish crypting. Returns the remaining partial block of output, if any.
     */
    pub fn final(&self) -> ~[u8] {
        unsafe {
            let mut res = vec::from_elem(self.blocksize, 0u8);

            let reslen = do res.as_mut_buf |pres, _len| {
                let mut reslen = self.blocksize as c_int;
                EVP_CipherFinal(self.ctx, pres, &mut reslen);
                reslen
            };

            res.slice(0u, reslen as uint).to_owned()
        }
    }
}

/**
 * Encrypts data, using the specified crypter type in encrypt mode with the
 * specified key and iv; returns the resulting (encrypted) data.
 */
pub fn encrypt(t: Type, key: &[u8], iv: ~[u8], data: &[u8]) -> ~[u8] {
    let c = Crypter(t);
    c.init(Encrypt, key, iv);
    let r = c.update(data);
    let rest = c.final();
    r + rest
}

/**
 * Decrypts data, using the specified crypter type in decrypt mode with the
 * specified key and iv; returns the resulting (decrypted) data.
 */
pub fn decrypt(t: Type, key: &[u8], iv: ~[u8], data: &[u8]) -> ~[u8] {
    let c = Crypter(t);
    c.init(Decrypt, key, iv);
    let r = c.update(data);
    let rest = c.final();
    r + rest
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::FromHex;

    // Test vectors from FIPS-197:
    // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    #[test]
    fn test_aes_256_ecb() {
        let k0 =
           ~[ 0x00u8, 0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8,
              0x08u8, 0x09u8, 0x0au8, 0x0bu8, 0x0cu8, 0x0du8, 0x0eu8, 0x0fu8,
              0x10u8, 0x11u8, 0x12u8, 0x13u8, 0x14u8, 0x15u8, 0x16u8, 0x17u8,
              0x18u8, 0x19u8, 0x1au8, 0x1bu8, 0x1cu8, 0x1du8, 0x1eu8, 0x1fu8 ];
        let p0 =
           ~[ 0x00u8, 0x11u8, 0x22u8, 0x33u8, 0x44u8, 0x55u8, 0x66u8, 0x77u8,
              0x88u8, 0x99u8, 0xaau8, 0xbbu8, 0xccu8, 0xddu8, 0xeeu8, 0xffu8 ];
        let c0 =
           ~[ 0x8eu8, 0xa2u8, 0xb7u8, 0xcau8, 0x51u8, 0x67u8, 0x45u8, 0xbfu8,
              0xeau8, 0xfcu8, 0x49u8, 0x90u8, 0x4bu8, 0x49u8, 0x60u8, 0x89u8 ];
        let c = Crypter(AES_256_ECB);
        c.init(Encrypt, k0, []);
        c.pad(false);
        let r0 = c.update(p0) + c.final();
        assert!(r0 == c0);
        c.init(Decrypt, k0, []);
        c.pad(false);
        let p1 = c.update(r0) + c.final();
        assert!(p1 == p0);
    }

    fn cipher_test(ciphertype: Type, pt: ~str, ct: ~str, key: ~str, iv: ~str) {
        use hex::ToHex;

        let cipher = Crypter(ciphertype);
        cipher.init(Encrypt, key.from_hex(), iv.from_hex());

        let expected = ct.from_hex();
        let computed = cipher.update(pt.from_hex()) + cipher.final();

        if computed != expected {
            println(fmt!("Computed: %s", computed.to_hex()));
            println(fmt!("Expected: %s", expected.to_hex()));
            if computed.len() != expected.len() {
                println(fmt!("Lengths differ: %u in computed vs %u expected",
                             computed.len(), expected.len()));
            }
            fail!(~"test failure");
        }
    }

    #[test]
    fn test_rc4() {

        let pt = ~"0000000000000000000000000000000000000000000000000000000000000000000000000000";
        let ct = ~"A68686B04D686AA107BD8D4CAB191A3EEC0A6294BC78B60F65C25CB47BD7BB3A48EFC4D26BE4";
        let key = ~"97CD440324DA5FD1F7955C1C13B6B466";
        let iv = ~"";

        cipher_test(RC4_128, pt, ct, key, iv);
    }

    /*#[test]
    fn test_aes128_ctr() {

        let pt = ~"6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
        let ct = ~"874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE";
        let key = ~"2B7E151628AED2A6ABF7158809CF4F3C";
        let iv = ~"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

        cipher_test(AES_128_CTR, pt, ct, key, iv);
    }*/

    /*#[test]
    fn test_aes128_gcm() {
        // Test case 3 in GCM spec
        let pt = ~"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let ct = ~"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4";
        let key = ~"feffe9928665731c6d6a8f9467308308";
        let iv = ~"cafebabefacedbaddecaf888";

        cipher_test(AES_128_GCM, pt, ct, key, iv);
    }*/

}
