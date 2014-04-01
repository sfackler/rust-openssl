use std::cast;
use std::libc::{c_char, c_int, c_uint};
use std::libc;
use std::ptr;
use std::slice;
use crypto::hash::{HashType, MD5, SHA1, SHA224, SHA256, SHA384, SHA512};

#[allow(non_camel_case_types)]
pub type EVP_PKEY = *libc::c_void;

#[allow(non_camel_case_types)]
pub type RSA = *libc::c_void;

#[link(name = "crypto")]
extern {
    fn EVP_PKEY_new() -> *EVP_PKEY;
    fn EVP_PKEY_free(k: *EVP_PKEY);
    fn EVP_PKEY_assign(pkey: *EVP_PKEY, typ: c_int, key: *c_char) -> c_int;
    fn EVP_PKEY_get1_RSA(k: *EVP_PKEY) -> *RSA;

    fn i2d_PublicKey(k: *EVP_PKEY, buf: **mut u8) -> c_int;
    fn d2i_PublicKey(t: c_int, k: **EVP_PKEY, buf: **u8, len: c_uint) -> *EVP_PKEY;
    fn i2d_PrivateKey(k: *EVP_PKEY, buf: **mut u8) -> c_int;
    fn d2i_PrivateKey(t: c_int, k: **EVP_PKEY, buf: **u8, len: c_uint) -> *EVP_PKEY;

    fn RSA_generate_key(modsz: c_uint, e: c_uint, cb: *u8, cbarg: *u8) -> *RSA;
    fn RSA_size(k: *RSA) -> c_uint;

    fn RSA_public_encrypt(flen: c_uint, from: *u8, to: *mut u8, k: *RSA,
                          pad: c_int) -> c_int;
    fn RSA_private_decrypt(flen: c_uint, from: *u8, to: *mut u8, k: *RSA,
                           pad: c_int) -> c_int;
    fn RSA_sign(t: c_int, m: *u8, mlen: c_uint, sig: *mut u8, siglen: *mut c_uint,
                k: *RSA) -> c_int;
    fn RSA_verify(t: c_int, m: *u8, mlen: c_uint, sig: *u8, siglen: c_uint,
                  k: *RSA) -> c_int;
}

enum Parts {
    Neither,
    Public,
    Both
}

/// Represents a role an asymmetric key might be appropriate for.
pub enum Role {
    Encrypt,
    Decrypt,
    Sign,
    Verify
}

/// Type of encryption padding to use.
pub enum EncryptionPadding {
    OAEP,
    PKCS1v15
}

fn openssl_padding_code(padding: EncryptionPadding) -> c_int {
    match padding {
        OAEP => 4,
        PKCS1v15 => 1
    }
}

fn openssl_hash_nid(hash: HashType) -> c_int {
    match hash {
        MD5    => 4,   // NID_md5,
        SHA1   => 64,  // NID_sha1
        SHA224 => 675, // NID_sha224
        SHA256 => 672, // NID_sha256
        SHA384 => 673, // NID_sha384
        SHA512 => 674, // NID_sha512
    }
}

pub struct PKey {
    evp: *EVP_PKEY,
    parts: Parts,
}

/// Represents a public key, optionally with a private key attached.
impl PKey {
    pub fn new() -> PKey {
        unsafe {
            PKey {
                evp: EVP_PKEY_new(),
                parts: Neither,
            }
        }
    }

    fn _tostr(&self, f: extern "C" unsafe fn(*EVP_PKEY, **mut u8) -> c_int) -> ~[u8] {
        unsafe {
            let len = f(self.evp, ptr::null());
            if len < 0 as c_int { return ~[]; }
            let mut s = slice::from_elem(len as uint, 0u8);

            let r = f(self.evp, &s.as_mut_ptr());

            s.truncate(r as uint);
            s
        }
    }

    fn _fromstr(&mut self, s: &[u8], f: extern "C" unsafe fn(c_int, **EVP_PKEY, **u8, c_uint) -> *EVP_PKEY) {
        unsafe {
            let evp = ptr::null();
            f(6 as c_int, &evp, &s.as_ptr(), s.len() as c_uint);
            self.evp = evp;
        }
    }

    pub fn gen(&mut self, keysz: uint) {
        unsafe {
            let rsa = RSA_generate_key(
                keysz as c_uint,
                65537u as c_uint,
                ptr::null(),
                ptr::null()
            );

            // XXX: 6 == NID_rsaEncryption
            EVP_PKEY_assign(
                self.evp,
                6 as c_int,
                cast::transmute(rsa));

            self.parts = Both;
        }
    }

    /**
     * Returns a serialized form of the public key, suitable for load_pub().
     */
    pub fn save_pub(&self) -> ~[u8] {
        self._tostr(i2d_PublicKey)
    }

    /**
     * Loads a serialized form of the public key, as produced by save_pub().
     */
    pub fn load_pub(&mut self, s: &[u8]) {
        self._fromstr(s, d2i_PublicKey);
        self.parts = Public;
    }

    /**
     * Returns a serialized form of the public and private keys, suitable for
     * load_priv().
     */
    pub fn save_priv(&self) -> ~[u8] {
        self._tostr(i2d_PrivateKey)
    }
    /**
     * Loads a serialized form of the public and private keys, as produced by
     * save_priv().
     */
    pub fn load_priv(&mut self, s: &[u8]) {
        self._fromstr(s, d2i_PrivateKey);
        self.parts = Both;
    }

    /**
     * Returns the size of the public key modulus.
     */
    pub fn size(&self) -> uint {
        unsafe {
            RSA_size(EVP_PKEY_get1_RSA(self.evp)) as uint
        }
    }

    /**
     * Returns whether this pkey object can perform the specified role.
     */
    pub fn can(&self, r: Role) -> bool {
        match r {
            Encrypt =>
                match self.parts {
                    Neither => false,
                    _ => true,
                },
            Verify =>
                match self.parts {
                    Neither => false,
                    _ => true,
                },
            Decrypt =>
                match self.parts {
                    Both => true,
                    _ => false,
                },
            Sign =>
                match self.parts {
                    Both => true,
                    _ => false,
                },
        }
    }

    /**
     * Returns the maximum amount of data that can be encrypted by an encrypt()
     * call.
     */
    pub fn max_data(&self) -> uint {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let len = RSA_size(rsa);

            // 41 comes from RSA_public_encrypt(3) for OAEP
            len as uint - 41u
        }
    }

    pub fn encrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> ~[u8] {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let len = RSA_size(rsa);

            assert!(s.len() < self.max_data());

            let mut r = slice::from_elem(len as uint + 1u, 0u8);

            let rv = RSA_public_encrypt(
                s.len() as c_uint,
                s.as_ptr(),
                r.as_mut_ptr(),
                rsa,
                openssl_padding_code(padding));

            if rv < 0 as c_int {
                ~[]
            } else {
                r.truncate(rv as uint);
                r
            }
        }
    }

    pub fn decrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> ~[u8] {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let len = RSA_size(rsa);

            assert_eq!(s.len() as c_uint, RSA_size(rsa));

            let mut r = slice::from_elem(len as uint + 1u, 0u8);

            let rv = RSA_private_decrypt(
                s.len() as c_uint,
                s.as_ptr(),
                r.as_mut_ptr(),
                rsa,
                openssl_padding_code(padding));

            if rv < 0 as c_int {
                ~[]
            } else {
                r.truncate(rv as uint);
                r
            }
        }
    }

    /**
     * Encrypts data using OAEP padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    pub fn encrypt(&self, s: &[u8]) -> ~[u8] { self.encrypt_with_padding(s, OAEP) }

    /**
     * Decrypts data, expecting OAEP padding, returning the decrypted data.
     */
    pub fn decrypt(&self, s: &[u8]) -> ~[u8] { self.decrypt_with_padding(s, OAEP) }

    /**
     * Signs data, using OpenSSL's default scheme and sha256. Unlike encrypt(),
     * can process an arbitrary amount of data; returns the signature.
     */
    pub fn sign(&self, s: &[u8]) -> ~[u8] { self.sign_with_hash(s, SHA256) }

    /**
     * Verifies a signature s (using OpenSSL's default scheme and sha256) on a
     * message m. Returns true if the signature is valid, and false otherwise.
     */
    pub fn verify(&self, m: &[u8], s: &[u8]) -> bool { self.verify_with_hash(m, s, SHA256) }

    pub fn sign_with_hash(&self, s: &[u8], hash: HashType) -> ~[u8] {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let mut len = RSA_size(rsa);
            let mut r = slice::from_elem(len as uint + 1u, 0u8);

            let rv = RSA_sign(
                openssl_hash_nid(hash),
                s.as_ptr(),
                s.len() as c_uint,
                r.as_mut_ptr(),
                &mut len,
                rsa);

            if rv < 0 as c_int {
                ~[]
            } else {
                r.truncate(len as uint);
                r
            }
        }
    }

    pub fn verify_with_hash(&self, m: &[u8], s: &[u8], hash: HashType) -> bool {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);

            let rv = RSA_verify(
                openssl_hash_nid(hash),
                m.as_ptr(),
                m.len() as c_uint,
                s.as_ptr(),
                s.len() as c_uint,
                rsa
            );

            rv == 1 as c_int
        }
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.evp);
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::hash::{MD5, SHA1};

    #[test]
    fn test_gen_pub() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        assert_eq!(k0.save_pub(), k1.save_pub());
        assert_eq!(k0.size(), k1.size());
        assert!(k0.can(super::Encrypt));
        assert!(k0.can(super::Decrypt));
        assert!(k0.can(super::Verify));
        assert!(k0.can(super::Sign));
        assert!(k1.can(super::Encrypt));
        assert!(!k1.can(super::Decrypt));
        assert!(k1.can(super::Verify));
        assert!(!k1.can(super::Sign));
    }

    #[test]
    fn test_gen_priv() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        k0.gen(512u);
        k1.load_priv(k0.save_priv());
        assert_eq!(k0.save_priv(), k1.save_priv());
        assert_eq!(k0.size(), k1.size());
        assert!(k0.can(super::Encrypt));
        assert!(k0.can(super::Decrypt));
        assert!(k0.can(super::Verify));
        assert!(k0.can(super::Sign));
        assert!(k1.can(super::Encrypt));
        assert!(k1.can(super::Decrypt));
        assert!(k1.can(super::Verify));
        assert!(k1.can(super::Sign));
    }

    #[test]
    fn test_encrypt() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = ~[0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        let emsg = k1.encrypt(msg);
        let dmsg = k0.decrypt(emsg);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_encrypt_pkcs() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = ~[0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        let emsg = k1.encrypt_with_padding(msg, super::PKCS1v15);
        let dmsg = k0.decrypt_with_padding(emsg, super::PKCS1v15);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_sign() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = ~[0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());
        let sig = k0.sign(msg);
        let rv = k1.verify(msg, sig);
        assert!(rv == true);
    }

    #[test]
    fn test_sign_hashes() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = ~[0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512u);
        k1.load_pub(k0.save_pub());

        let sig = k0.sign_with_hash(msg, MD5);

        assert!(k1.verify_with_hash(msg, sig, MD5));
        assert!(!k1.verify_with_hash(msg, sig, SHA1));
    }
}
