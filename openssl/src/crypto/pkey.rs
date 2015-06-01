use libc::{c_int, c_uint, c_ulong};
use std::io;
use std::io::prelude::*;
use std::iter::repeat;
use std::mem;
use std::ptr;
use bio::{MemBio};
use crypto::hash;
use crypto::hash::Type as HashType;
use ffi;
use ssl::error::{SslError, StreamError};

#[derive(Copy, Clone)]
pub enum Parts {
    Neither,
    Public,
    Both
}

/// Represents a role an asymmetric key might be appropriate for.
#[derive(Copy, Clone)]
pub enum Role {
    Encrypt,
    Decrypt,
    Sign,
    Verify
}

/// Type of encryption padding to use.
#[derive(Copy, Clone)]
pub enum EncryptionPadding {
    OAEP,
    PKCS1v15
}

fn openssl_padding_code(padding: EncryptionPadding) -> c_int {
    match padding {
        EncryptionPadding::OAEP => 4,
        EncryptionPadding::PKCS1v15 => 1
    }
}

fn openssl_hash_nid(hash: HashType) -> c_int {
    match hash {
        HashType::MD5       => 4,   // NID_md5,
        HashType::SHA1      => 64,  // NID_sha1
        HashType::SHA224    => 675, // NID_sha224
        HashType::SHA256    => 672, // NID_sha256
        HashType::SHA384    => 673, // NID_sha384
        HashType::SHA512    => 674, // NID_sha512
        HashType::RIPEMD160 => 117, // NID_ripemd160
    }
}

pub struct PKey {
    evp: *mut ffi::EVP_PKEY,
    parts: Parts,
}

/// Represents a public key, optionally with a private key attached.
impl PKey {
    pub fn new() -> PKey {
        unsafe {
            ffi::init();

            PKey {
                evp: ffi::EVP_PKEY_new(),
                parts: Parts::Neither,
            }
        }
    }

    pub fn from_handle(handle: *mut ffi::EVP_PKEY, parts: Parts) -> PKey {
        ffi::init();
        assert!(!handle.is_null());

        PKey {
            evp: handle,
            parts: parts,
        }
    }

    /// Reads private key from PEM, takes ownership of handle
    pub fn private_key_from_pem<R>(reader: &mut R) -> Result<PKey, SslError> where R: Read {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let evp = try_ssl_null!(ffi::PEM_read_bio_PrivateKey(mem_bio.get_handle(),
                                                                 ptr::null_mut(),
                                                                 None, ptr::null_mut()));
            Ok(PKey {
                evp:   evp,
                parts: Parts::Both,
            })
        }
    }

    fn _tostr(&self, f: unsafe extern "C" fn(*mut ffi::RSA, *const *mut u8) -> c_int) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            let len = f(rsa, ptr::null());
            if len < 0 as c_int { return vec!(); }
            let mut s = repeat(0u8).take(len as usize).collect::<Vec<_>>();

            let r = f(rsa, &s.as_mut_ptr());

            s.truncate(r as usize);
            s
        }
    }

    fn _fromstr(&mut self, s: &[u8], f: unsafe extern "C" fn(*const *mut ffi::RSA, *const *const u8, c_uint) -> *mut ffi::RSA) {
        unsafe {
            let rsa = ptr::null_mut();
            f(&rsa, &s.as_ptr(), s.len() as c_uint);
            ffi::EVP_PKEY_set1_RSA(self.evp, rsa);
        }
    }

    pub fn gen(&mut self, keysz: usize) {
        unsafe {
            let rsa = ffi::RSA_generate_key(
                keysz as c_int,
                65537 as c_ulong,
                ptr::null(),
                ptr::null()
            );

            // XXX: 6 == NID_rsaEncryption
            ffi::EVP_PKEY_assign(
                self.evp,
                6 as c_int,
                mem::transmute(rsa));

            self.parts = Parts::Both;
        }
    }

    /**
     * Returns a serialized form of the public key, suitable for load_pub().
     */
    pub fn save_pub(&self) -> Vec<u8> {
        self._tostr(ffi::i2d_RSA_PUBKEY)
    }

    /**
     * Loads a serialized form of the public key, as produced by save_pub().
     */
    pub fn load_pub(&mut self, s: &[u8]) {
        self._fromstr(s, ffi::d2i_RSA_PUBKEY);
        self.parts = Parts::Public;
    }

    /**
     * Returns a serialized form of the public and private keys, suitable for
     * load_priv().
     */
    pub fn save_priv(&self) -> Vec<u8> {
        self._tostr(ffi::i2d_RSAPrivateKey)
    }
    /**
     * Loads a serialized form of the public and private keys, as produced by
     * save_priv().
     */
    pub fn load_priv(&mut self, s: &[u8]) {
        self._fromstr(s, ffi::d2i_RSAPrivateKey);
        self.parts = Parts::Both;
    }

    /// Stores private key as a PEM
    // FIXME: also add password and encryption
    pub fn write_pem<W: Write>(&self, writer: &mut W/*, password: Option<String>*/) -> Result<(), SslError> {
        let mut mem_bio = try!(MemBio::new());
        unsafe {
            try_ssl!(ffi::PEM_write_bio_PrivateKey(mem_bio.get_handle(), self.evp, ptr::null(),
                                                   ptr::null_mut(), -1, None, ptr::null_mut()));

        }
        let mut buf = vec![];
        try!(mem_bio.read_to_end(&mut buf).map_err(StreamError));
        writer.write_all(&buf).map_err(StreamError)
    }

    /**
     * Returns the size of the public key modulus.
     */
    pub fn size(&self) -> usize {
        unsafe {
            ffi::RSA_size(ffi::EVP_PKEY_get1_RSA(self.evp)) as usize
        }
    }

    /**
     * Returns whether this pkey object can perform the specified role.
     */
    pub fn can(&self, r: Role) -> bool {
        match r {
            Role::Encrypt =>
                match self.parts {
                    Parts::Neither => false,
                    _ => true,
                },
            Role::Verify =>
                match self.parts {
                    Parts::Neither => false,
                    _ => true,
                },
            Role::Decrypt =>
                match self.parts {
                    Parts::Both => true,
                    _ => false,
                },
            Role::Sign =>
                match self.parts {
                    Parts::Both => true,
                    _ => false,
                },
        }
    }

    /**
     * Returns the maximum amount of data that can be encrypted by an encrypt()
     * call.
     */
    pub fn max_data(&self) -> usize {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            let len = ffi::RSA_size(rsa);

            // 41 comes from RSA_public_encrypt(3) for OAEP
            len as usize - 41
        }
    }

    pub fn encrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            let len = ffi::RSA_size(rsa);

            assert!(s.len() < self.max_data());

            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let rv = ffi::RSA_public_encrypt(
                s.len() as c_int,
                s.as_ptr(),
                r.as_mut_ptr(),
                rsa,
                openssl_padding_code(padding));

            if rv < 0 as c_int {
                vec!()
            } else {
                r.truncate(rv as usize);
                r
            }
        }
    }

    pub fn decrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            let len = ffi::RSA_size(rsa);

            assert_eq!(s.len() as c_int, ffi::RSA_size(rsa));

            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let rv = ffi::RSA_private_decrypt(
                s.len() as c_int,
                s.as_ptr(),
                r.as_mut_ptr(),
                rsa,
                openssl_padding_code(padding));

            if rv < 0 as c_int {
                vec!()
            } else {
                r.truncate(rv as usize);
                r
            }
        }
    }

    /**
     * Encrypts data using OAEP padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    pub fn encrypt(&self, s: &[u8]) -> Vec<u8> { self.encrypt_with_padding(s, EncryptionPadding::OAEP) }

    /**
     * Decrypts data, expecting OAEP padding, returning the decrypted data.
     */
    pub fn decrypt(&self, s: &[u8]) -> Vec<u8> { self.decrypt_with_padding(s, EncryptionPadding::OAEP) }

    /**
     * Signs data, using OpenSSL's default scheme and adding sha256 ASN.1 information to the
     * signature.
     * The bytes to sign must be the result of a sha256 hashing;
     * returns the signature.
     */
    pub fn sign(&self, s: &[u8]) -> Vec<u8> { self.sign_with_hash(s, HashType::SHA256) }

    /**
     * Verifies a signature s (using OpenSSL's default scheme and sha256) on the SHA256 hash of a
     * message.
     * Returns true if the signature is valid, and false otherwise.
     */
    pub fn verify(&self, h: &[u8], s: &[u8]) -> bool { self.verify_with_hash(h, s, HashType::SHA256) }

    /**
     * Signs data, using OpenSSL's default scheme and add ASN.1 information for the given hash type to the
     * signature.
     * The bytes to sign must be the result of this type of hashing;
     * returns the signature.
     */
    pub fn sign_with_hash(&self, s: &[u8], hash: hash::Type) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            let len = ffi::RSA_size(rsa);
            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let mut len = 0;
            let rv = ffi::RSA_sign(
                openssl_hash_nid(hash),
                s.as_ptr(),
                s.len() as c_uint,
                r.as_mut_ptr(),
                &mut len,
                rsa);

            if rv < 0 as c_int {
                vec!()
            } else {
                r.truncate(len as usize);
                r
            }
        }
    }

    pub fn verify_with_hash(&self, h: &[u8], s: &[u8], hash: hash::Type) -> bool {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);

            let rv = ffi::RSA_verify(
                openssl_hash_nid(hash),
                h.as_ptr(),
                h.len() as c_uint,
                s.as_ptr(),
                s.len() as c_uint,
                rsa
            );

            rv == 1 as c_int
        }
    }

    pub unsafe fn get_handle(&self) -> *mut ffi::EVP_PKEY {
        return self.evp
    }

    pub fn public_eq(&self, other: &PKey) -> bool {
        unsafe { ffi::EVP_PKEY_cmp(self.evp, other.evp) == 1 }
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_PKEY_free(self.evp);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::fs::File;
    use crypto::hash::Type::{MD5, SHA1};

    #[test]
    fn test_gen_pub() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        k0.gen(512);
        k1.load_pub(&k0.save_pub());
        assert_eq!(k0.save_pub(), k1.save_pub());
        assert!(k0.public_eq(&k1));
        assert_eq!(k0.size(), k1.size());
        assert!(k0.can(super::Role::Encrypt));
        assert!(k0.can(super::Role::Decrypt));
        assert!(k0.can(super::Role::Verify));
        assert!(k0.can(super::Role::Sign));
        assert!(k1.can(super::Role::Encrypt));
        assert!(!k1.can(super::Role::Decrypt));
        assert!(k1.can(super::Role::Verify));
        assert!(!k1.can(super::Role::Sign));
    }

    #[test]
    fn test_gen_priv() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        k0.gen(512);
        k1.load_priv(&k0.save_priv());
        assert_eq!(k0.save_priv(), k1.save_priv());
        assert!(k0.public_eq(&k1));
        assert_eq!(k0.size(), k1.size());
        assert!(k0.can(super::Role::Encrypt));
        assert!(k0.can(super::Role::Decrypt));
        assert!(k0.can(super::Role::Verify));
        assert!(k0.can(super::Role::Sign));
        assert!(k1.can(super::Role::Encrypt));
        assert!(k1.can(super::Role::Decrypt));
        assert!(k1.can(super::Role::Verify));
        assert!(k1.can(super::Role::Sign));
    }

    #[test]
    fn test_private_key_from_pem() {
        let key_path = Path::new("test/key.pem");
        let mut file = File::open(&key_path)
            .ok()
            .expect("Failed to open `test/key.pem`");

        super::PKey::private_key_from_pem(&mut file).unwrap();
    }

    #[test]
    fn test_encrypt() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512);
        k1.load_pub(&k0.save_pub());
        let emsg = k1.encrypt(&msg);
        let dmsg = k0.decrypt(&emsg);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_encrypt_pkcs() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512);
        k1.load_pub(&k0.save_pub());
        let emsg = k1.encrypt_with_padding(&msg, super::EncryptionPadding::PKCS1v15);
        let dmsg = k0.decrypt_with_padding(&emsg, super::EncryptionPadding::PKCS1v15);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_sign() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512);
        k1.load_pub(&k0.save_pub());
        let sig = k0.sign(&msg);
        let rv = k1.verify(&msg, &sig);
        assert!(rv == true);
    }

    #[test]
    fn test_sign_hashes() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);
        k0.gen(512);
        k1.load_pub(&k0.save_pub());

        let sig = k0.sign_with_hash(&msg, MD5);

        assert!(k1.verify_with_hash(&msg, &sig, MD5));
        assert!(!k1.verify_with_hash(&msg, &sig, SHA1));
    }

    #[test]
    fn test_eq() {
        let mut k0 = super::PKey::new();
        let mut p0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let mut p1 = super::PKey::new();
        k0.gen(512);
        k1.gen(512);
        p0.load_pub(&k0.save_pub());
        p1.load_pub(&k1.save_pub());

        assert!(k0.public_eq(&k0));
        assert!(k1.public_eq(&k1));
        assert!(p0.public_eq(&p0));
        assert!(p1.public_eq(&p1));
        assert!(k0.public_eq(&p0));
        assert!(k1.public_eq(&p1));

        assert!(!k0.public_eq(&k1));
        assert!(!p0.public_eq(&p1));
        assert!(!k0.public_eq(&p1));
        assert!(!p0.public_eq(&k1));
    }
}
