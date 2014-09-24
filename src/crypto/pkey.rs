use libc::{c_char, c_int, c_uint, c_void};
use libc;
use std::mem;
use std::ptr;
use bio::{mod, MemBio};
use crypto::hash::{HashType, MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160};
use crypto::symm::{EVP_CIPHER};
use ssl::error::{SslError, StreamError};

#[allow(non_camel_case_types)]
pub type EVP_PKEY = *mut libc::c_void;

#[allow(non_camel_case_types)]
pub type RSA = *mut libc::c_void;

pub type PrivateKeyWriteCallback = extern "C" fn(buf: *mut c_char, size: c_int, rwflag: c_int, user_data: *mut c_void) -> c_int;

#[link(name = "crypto")]
extern {
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn EVP_PKEY_assign(pkey: *mut EVP_PKEY, typ: c_int, key: *const c_char) -> c_int;
    fn EVP_PKEY_get1_RSA(k: *mut EVP_PKEY) -> *mut RSA;
    fn EVP_PKEY_set1_RSA(k: *mut EVP_PKEY, r: *mut RSA) -> c_int;

    fn i2d_RSA_PUBKEY(k: *mut RSA, buf: *const *mut u8) -> c_int;
    fn d2i_RSA_PUBKEY(k: *const *mut RSA, buf: *const *const u8, len: c_uint) -> *mut RSA;
    fn i2d_RSAPrivateKey(k: *mut RSA, buf: *const *mut u8) -> c_int;
    fn d2i_RSAPrivateKey(k: *const *mut RSA, buf: *const *const u8, len: c_uint) -> *mut RSA;

    fn RSA_generate_key(modsz: c_uint, e: c_uint, cb: *const u8, cbarg: *const u8) -> *mut RSA;
    fn RSA_size(k: *mut RSA) -> c_uint;

    fn RSA_public_encrypt(flen: c_uint, from: *const u8, to: *mut u8, k: *mut RSA,
                          pad: c_int) -> c_int;
    fn RSA_private_decrypt(flen: c_uint, from: *const u8, to: *mut u8, k: *mut RSA,
                           pad: c_int) -> c_int;
    fn RSA_sign(t: c_int, m: *const u8, mlen: c_uint, sig: *mut u8, siglen: *mut c_uint,
                k: *mut RSA) -> c_int;
    fn RSA_verify(t: c_int, m: *const u8, mlen: c_uint, sig: *const u8, siglen: c_uint,
                  k: *mut RSA) -> c_int;

    fn PEM_write_bio_PrivateKey(bio: *mut bio::ffi::BIO, pkey: *mut EVP_PKEY, cipher: *const EVP_CIPHER,
                                kstr: *mut c_char, klen: c_int,
                                callback: *mut c_void,
                                user_data: *mut c_void) -> c_int;
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
        MD5       => 4,   // NID_md5,
        SHA1      => 64,  // NID_sha1
        SHA224    => 675, // NID_sha224
        SHA256    => 672, // NID_sha256
        SHA384    => 673, // NID_sha384
        SHA512    => 674, // NID_sha512
        RIPEMD160 => 117, // NID_ripemd160
    }
}

pub struct PKey {
    evp: *mut EVP_PKEY,
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

    fn _tostr(&self, f: unsafe extern "C" fn(*mut RSA, *const *mut u8) -> c_int) -> Vec<u8> {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let len = f(rsa, ptr::null());
            if len < 0 as c_int { return vec!(); }
            let mut s = Vec::from_elem(len as uint, 0u8);

            let r = f(rsa, &s.as_mut_ptr());

            s.truncate(r as uint);
            s
        }
    }

    fn _fromstr(&mut self, s: &[u8], f: unsafe extern "C" fn(*const *mut RSA, *const *const u8, c_uint) -> *mut RSA) {
        unsafe {
            let rsa = ptr::null_mut();
            f(&rsa, &s.as_ptr(), s.len() as c_uint);
            EVP_PKEY_set1_RSA(self.evp, rsa);
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
                mem::transmute(rsa));

            self.parts = Both;
        }
    }

    /**
     * Returns a serialized form of the public key, suitable for load_pub().
     */
    pub fn save_pub(&self) -> Vec<u8> {
        self._tostr(i2d_RSA_PUBKEY)
    }

    /**
     * Loads a serialized form of the public key, as produced by save_pub().
     */
    pub fn load_pub(&mut self, s: &[u8]) {
        self._fromstr(s, d2i_RSA_PUBKEY);
        self.parts = Public;
    }

    /**
     * Returns a serialized form of the public and private keys, suitable for
     * load_priv().
     */
    pub fn save_priv(&self) -> Vec<u8> {
        self._tostr(i2d_RSAPrivateKey)
    }
    /**
     * Loads a serialized form of the public and private keys, as produced by
     * save_priv().
     */
    pub fn load_priv(&mut self, s: &[u8]) {
        self._fromstr(s, d2i_RSAPrivateKey);
        self.parts = Both;
    }

    /// Stores private key as a PEM
    // FIXME: also add password and encryption
    pub fn write_pem(&self, writer: &mut Writer/*, password: Option<String>*/) -> Result<(), SslError> {
        let mut mem_bio = try!(MemBio::new());
        unsafe {
            try_ssl!(PEM_write_bio_PrivateKey(mem_bio.get_handle(), self.evp, ptr::null(),
                                              ptr::null_mut(), -1, ptr::null_mut(), ptr::null_mut()));

        }
        let buf = try!(mem_bio.read_to_end().map_err(StreamError));
        writer.write(buf.as_slice()).map_err(StreamError)
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

    pub fn encrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let len = RSA_size(rsa);

            assert!(s.len() < self.max_data());

            let mut r = Vec::from_elem(len as uint + 1u, 0u8);

            let rv = RSA_public_encrypt(
                s.len() as c_uint,
                s.as_ptr(),
                r.as_mut_ptr(),
                rsa,
                openssl_padding_code(padding));

            if rv < 0 as c_int {
                vec!()
            } else {
                r.truncate(rv as uint);
                r
            }
        }
    }

    pub fn decrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let len = RSA_size(rsa);

            assert_eq!(s.len() as c_uint, RSA_size(rsa));

            let mut r = Vec::from_elem(len as uint + 1u, 0u8);

            let rv = RSA_private_decrypt(
                s.len() as c_uint,
                s.as_ptr(),
                r.as_mut_ptr(),
                rsa,
                openssl_padding_code(padding));

            if rv < 0 as c_int {
                vec!()
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
    pub fn encrypt(&self, s: &[u8]) -> Vec<u8> { self.encrypt_with_padding(s, OAEP) }

    /**
     * Decrypts data, expecting OAEP padding, returning the decrypted data.
     */
    pub fn decrypt(&self, s: &[u8]) -> Vec<u8> { self.decrypt_with_padding(s, OAEP) }

    /**
     * Signs data, using OpenSSL's default scheme and sha256. Unlike encrypt(),
     * can process an arbitrary amount of data; returns the signature.
     */
    pub fn sign(&self, s: &[u8]) -> Vec<u8> { self.sign_with_hash(s, SHA256) }

    /**
     * Verifies a signature s (using OpenSSL's default scheme and sha256) on a
     * message m. Returns true if the signature is valid, and false otherwise.
     */
    pub fn verify(&self, m: &[u8], s: &[u8]) -> bool { self.verify_with_hash(m, s, SHA256) }

    pub fn sign_with_hash(&self, s: &[u8], hash: HashType) -> Vec<u8> {
        unsafe {
            let rsa = EVP_PKEY_get1_RSA(self.evp);
            let mut len = RSA_size(rsa);
            let mut r = Vec::from_elem(len as uint + 1u, 0u8);

            let rv = RSA_sign(
                openssl_hash_nid(hash),
                s.as_ptr(),
                s.len() as c_uint,
                r.as_mut_ptr(),
                &mut len,
                rsa);

            if rv < 0 as c_int {
                vec!()
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

    pub unsafe fn get_handle(&self) -> *mut EVP_PKEY {
        return self.evp
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
        k1.load_pub(k0.save_pub().as_slice());
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
        k1.load_priv(k0.save_priv().as_slice());
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
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512u);
        k1.load_pub(k0.save_pub().as_slice());
        let emsg = k1.encrypt(msg.as_slice());
        let dmsg = k0.decrypt(emsg.as_slice());
        assert!(msg == dmsg);
    }

    #[test]
    fn test_encrypt_pkcs() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512u);
        k1.load_pub(k0.save_pub().as_slice());
        let emsg = k1.encrypt_with_padding(msg.as_slice(), super::PKCS1v15);
        let dmsg = k0.decrypt_with_padding(emsg.as_slice(), super::PKCS1v15);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_sign() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512u);
        k1.load_pub(k0.save_pub().as_slice());
        let sig = k0.sign(msg.as_slice());
        let rv = k1.verify(msg.as_slice(), sig.as_slice());
        assert!(rv == true);
    }

    #[test]
    fn test_sign_hashes() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512u);
        k1.load_pub(k0.save_pub().as_slice());

        let sig = k0.sign_with_hash(msg.as_slice(), MD5);

        assert!(k1.verify_with_hash(msg.as_slice(), sig.as_slice(), MD5));
        assert!(!k1.verify_with_hash(msg.as_slice(), sig.as_slice(), SHA1));
    }
}
