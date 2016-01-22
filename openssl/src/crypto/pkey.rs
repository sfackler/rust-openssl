use libc::{c_int, c_uint, c_ulong};
use std::io;
use std::io::prelude::*;
use std::iter::repeat;
use std::mem;
use std::ptr;
use bio::MemBio;
use crypto::hash;
use crypto::hash::Type as HashType;
use ffi;
use ssl::error::{SslError, StreamError};

#[derive(Copy, Clone)]
pub enum Parts {
    Neither,
    Public,
    Both,
}

/// Represents a role an asymmetric key might be appropriate for.
#[derive(Copy, Clone)]
pub enum Role {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

/// Type of encryption padding to use.
#[derive(Copy, Clone)]
pub enum EncryptionPadding {
    OAEP,
    PKCS1v15,
}

fn openssl_padding_code(padding: EncryptionPadding) -> c_int {
    match padding {
        EncryptionPadding::OAEP => 4,
        EncryptionPadding::PKCS1v15 => 1,
    }
}

fn openssl_hash_nid(hash: HashType) -> c_int {
    match hash {
        HashType::MD5 => 4,   // NID_md5,
        HashType::SHA1 => 64,  // NID_sha1
        HashType::SHA224 => 675, // NID_sha224
        HashType::SHA256 => 672, // NID_sha256
        HashType::SHA384 => 673, // NID_sha384
        HashType::SHA512 => 674, // NID_sha512
        HashType::RIPEMD160 => 117, // NID_ripemd160
    }
}

extern "C" {
    fn rust_EVP_PKEY_clone(pkey: *mut ffi::EVP_PKEY);
}

pub struct PKey {
    evp: *mut ffi::EVP_PKEY,
    parts: Parts,
}

unsafe impl Send for PKey {}
unsafe impl Sync for PKey {}

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
    pub fn private_key_from_pem<R>(reader: &mut R) -> Result<PKey, SslError>
        where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let evp = try_ssl_null!(ffi::PEM_read_bio_PrivateKey(mem_bio.get_handle(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            Ok(PKey {
                evp: evp,
                parts: Parts::Both,
            })
        }
    }

    /// Reads public key from PEM, takes ownership of handle
    pub fn public_key_from_pem<R>(reader: &mut R) -> Result<PKey, SslError>
        where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let evp = try_ssl_null!(ffi::PEM_read_bio_PUBKEY(mem_bio.get_handle(),
                                                             ptr::null_mut(),
                                                             None,
                                                             ptr::null_mut()));
            Ok(PKey {
                evp: evp,
                parts: Parts::Public,
            })
        }
    }

    /// Reads an RSA private key from PEM, takes ownership of handle
    pub fn private_rsa_key_from_pem<R>(reader: &mut R) -> Result<PKey, SslError>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.get_handle(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            let evp = ffi::EVP_PKEY_new();
            if ffi::EVP_PKEY_set1_RSA(evp, rsa) == 0 {
                return Err(SslError::get());
            }

            Ok(PKey {
                evp: evp,
                parts: Parts::Public,
            })
        }
    }

    /// Reads an RSA public key from PEM, takes ownership of handle
    pub fn public_rsa_key_from_pem<R>(reader: &mut R) -> Result<PKey, SslError>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSA_PUBKEY(mem_bio.get_handle(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            let evp = ffi::EVP_PKEY_new();
            if ffi::EVP_PKEY_set1_RSA(evp, rsa) == 0 {
                return Err(SslError::get());
            }

            Ok(PKey {
                evp: evp,
                parts: Parts::Public,
            })
        }
    }

    fn _tostr(&self, f: unsafe extern "C" fn(*mut ffi::RSA, *const *mut u8) -> c_int) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            let len = f(rsa, ptr::null());
            if len < 0 as c_int {
                return vec![];
            }
            let mut s = repeat(0u8).take(len as usize).collect::<Vec<_>>();

            let r = f(rsa, &s.as_mut_ptr());
            ffi::RSA_free(rsa);

            s.truncate(r as usize);
            s
        }
    }

    fn _fromstr(&mut self,
                s: &[u8],
                f: unsafe extern "C" fn(*const *mut ffi::RSA, *const *const u8, c_uint)
                                        -> *mut ffi::RSA)
                -> bool {
        unsafe {
            let rsa = ptr::null_mut();
            f(&rsa, &s.as_ptr(), s.len() as c_uint);
            if !rsa.is_null() {
                ffi::EVP_PKEY_set1_RSA(self.evp, rsa) == 1
            } else {
                false
            }
        }
    }

    pub fn gen(&mut self, keysz: usize) {
        unsafe {
            let rsa = ffi::RSA_generate_key(keysz as c_int,
                                            65537 as c_ulong,
                                            ptr::null(),
                                            ptr::null());

            // XXX: 6 == NID_rsaEncryption
            ffi::EVP_PKEY_assign(self.evp, 6 as c_int, mem::transmute(rsa));

            self.parts = Parts::Both;
        }
    }

    /**
     * Returns a DER serialized form of the public key, suitable for load_pub().
     */
    pub fn save_pub(&self) -> Vec<u8> {
        self._tostr(ffi::i2d_RSA_PUBKEY)
    }

    /**
     * Loads a DER serialized form of the public key, as produced by save_pub().
     */
    pub fn load_pub(&mut self, s: &[u8]) {
        if self._fromstr(s, ffi::d2i_RSA_PUBKEY) {
            self.parts = Parts::Public;
        }
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
        if self._fromstr(s, ffi::d2i_RSAPrivateKey) {
            self.parts = Parts::Both;
        }
    }

    /// Stores private key as a PEM
    // FIXME: also add password and encryption
    pub fn write_pem<W: Write>(&self,
                               writer: &mut W /* , password: Option<String> */)
                               -> Result<(), SslError> {
        let mut mem_bio = try!(MemBio::new());
        unsafe {
            try_ssl!(ffi::PEM_write_bio_PrivateKey(mem_bio.get_handle(),
                                                   self.evp,
                                                   ptr::null(),
                                                   ptr::null_mut(),
                                                   -1,
                                                   None,
                                                   ptr::null_mut()));

        }
        let mut buf = vec![];
        try!(mem_bio.read_to_end(&mut buf).map_err(StreamError));
        writer.write_all(&buf).map_err(StreamError)
    }

    /// Stores public key as a PEM
    pub fn write_pub_pem<W: Write>(&self,
                                   writer: &mut W /* , password: Option<String> */)
                                   -> Result<(), SslError> {
        let mut mem_bio = try!(MemBio::new());
        unsafe { try_ssl!(ffi::PEM_write_bio_PUBKEY(mem_bio.get_handle(), self.evp)) }
        let mut buf = vec![];
        try!(mem_bio.read_to_end(&mut buf).map_err(StreamError));
        writer.write_all(&buf).map_err(StreamError)
    }

    /**
     * Returns the size of the public key modulus.
     */
    pub fn size(&self) -> usize {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                0
            } else {
                ffi::RSA_size(rsa) as usize
            }
        }
    }

    /**
     * Returns whether this pkey object can perform the specified role.
     */
    pub fn can(&self, r: Role) -> bool {
        match r {
            Role::Encrypt => {
                match self.parts {
                    Parts::Neither => false,
                    _ => true,
                }
            }
            Role::Verify => {
                match self.parts {
                    Parts::Neither => false,
                    _ => true,
                }
            }
            Role::Decrypt => {
                match self.parts {
                    Parts::Both => true,
                    _ => false,
                }
            }
            Role::Sign => {
                match self.parts {
                    Parts::Both => true,
                    _ => false,
                }
            }
        }
    }

    /**
     * Returns the maximum amount of data that can be encrypted by an encrypt()
     * call.
     */
    pub fn max_data(&self) -> usize {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                return 0;
            }
            let len = ffi::RSA_size(rsa);

            // 41 comes from RSA_public_encrypt(3) for OAEP
            len as usize - 41
        }
    }

    pub fn private_encrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                panic!("Could not get RSA key for encryption");
            }
            let len = ffi::RSA_size(rsa);

            assert!(s.len() < self.max_data());

            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let rv = ffi::RSA_private_encrypt(s.len() as c_int,
                                              s.as_ptr(),
                                              r.as_mut_ptr(),
                                              rsa,
                                              openssl_padding_code(padding));

            if rv < 0 as c_int {
                // println!("{:?}", SslError::get());
                vec![]
            } else {
                r.truncate(rv as usize);
                r
            }
        }
    }

    pub fn public_encrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                panic!("Could not get RSA key for encryption");
            }
            let len = ffi::RSA_size(rsa);

            assert!(s.len() < self.max_data());

            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let rv = ffi::RSA_public_encrypt(s.len() as c_int,
                                             s.as_ptr(),
                                             r.as_mut_ptr(),
                                             rsa,
                                             openssl_padding_code(padding));

            if rv < 0 as c_int {
                vec![]
            } else {
                r.truncate(rv as usize);
                r
            }
        }
    }

    pub fn private_decrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                panic!("Could not get RSA key for decryption");
            }
            let len = ffi::RSA_size(rsa);

            assert_eq!(s.len() as c_int, ffi::RSA_size(rsa));

            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let rv = ffi::RSA_private_decrypt(s.len() as c_int,
                                              s.as_ptr(),
                                              r.as_mut_ptr(),
                                              rsa,
                                              openssl_padding_code(padding));

            if rv < 0 as c_int {
                vec![]
            } else {
                r.truncate(rv as usize);
                r
            }
        }
    }

    pub fn public_decrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                panic!("Could not get RSA key for decryption");
            }
            let len = ffi::RSA_size(rsa);

            assert_eq!(s.len() as c_int, ffi::RSA_size(rsa));

            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let rv = ffi::RSA_public_decrypt(s.len() as c_int,
                                             s.as_ptr(),
                                             r.as_mut_ptr(),
                                             rsa,
                                             openssl_padding_code(padding));

            if rv < 0 as c_int {
                vec![]
            } else {
                r.truncate(rv as usize);
                r
            }
        }
    }

    /**
     * Encrypts data with the public key, using OAEP padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    pub fn encrypt(&self, s: &[u8]) -> Vec<u8> {
        self.public_encrypt_with_padding(s, EncryptionPadding::OAEP)
    }

    /**
     * Encrypts data with the public key, using provided padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    pub fn encrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        self.public_encrypt_with_padding(s, padding)
    }

    /**
     * Encrypts data with the public key, using OAEP padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    pub fn public_encrypt(&self, s: &[u8]) -> Vec<u8> {
        self.public_encrypt_with_padding(s, EncryptionPadding::OAEP)
    }

    /**
     * Decrypts data with the public key, using PKCS1v15 padding, returning the decrypted data.
     */
    pub fn public_decrypt(&self, s: &[u8]) -> Vec<u8> {
        self.public_decrypt_with_padding(s, EncryptionPadding::PKCS1v15)
    }

    /**
     * Decrypts data with the private key, expecting OAEP padding, returning the decrypted data.
     */
    pub fn decrypt(&self, s: &[u8]) -> Vec<u8> {
        self.private_decrypt_with_padding(s, EncryptionPadding::OAEP)
    }

    /**
     * Decrypts data with the private key, using provided padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    pub fn decrypt_with_padding(&self, s: &[u8], padding: EncryptionPadding) -> Vec<u8> {
        self.private_decrypt_with_padding(s, padding)
    }

    /**
     * Decrypts data with the private key, expecting OAEP padding, returning the decrypted data.
     */
    pub fn private_decrypt(&self, s: &[u8]) -> Vec<u8> {
        self.private_decrypt_with_padding(s, EncryptionPadding::OAEP)
    }

    /**
     * Encrypts data with the private key, using PKCS1v15 padding, returning the encrypted data. The
     * supplied data must not be larger than max_data().
     */
    pub fn private_encrypt(&self, s: &[u8]) -> Vec<u8> {
        self.private_encrypt_with_padding(s, EncryptionPadding::PKCS1v15)
    }

    /**
     * Signs data, using OpenSSL's default scheme and adding sha256 ASN.1 information to the
     * signature.
     * The bytes to sign must be the result of a sha256 hashing;
     * returns the signature.
     */
    pub fn sign(&self, s: &[u8]) -> Vec<u8> {
        self.sign_with_hash(s, HashType::SHA256)
    }

    /**
     * Verifies a signature s (using OpenSSL's default scheme and sha256) on the SHA256 hash of a
     * message.
     * Returns true if the signature is valid, and false otherwise.
     */
    pub fn verify(&self, h: &[u8], s: &[u8]) -> bool {
        self.verify_with_hash(h, s, HashType::SHA256)
    }

    /**
     * Signs data, using OpenSSL's default scheme and add ASN.1 information for the given hash type to the
     * signature.
     * The bytes to sign must be the result of this type of hashing;
     * returns the signature.
     */
    pub fn sign_with_hash(&self, s: &[u8], hash: hash::Type) -> Vec<u8> {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                panic!("Could not get RSA key for signing");
            }
            let len = ffi::RSA_size(rsa);
            let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

            let mut len = 0;
            let rv = ffi::RSA_sign(openssl_hash_nid(hash),
                                   s.as_ptr(),
                                   s.len() as c_uint,
                                   r.as_mut_ptr(),
                                   &mut len,
                                   rsa);

            if rv < 0 as c_int {
                vec![]
            } else {
                r.truncate(len as usize);
                r
            }
        }
    }

    pub fn verify_with_hash(&self, h: &[u8], s: &[u8], hash: hash::Type) -> bool {
        unsafe {
            let rsa = ffi::EVP_PKEY_get1_RSA(self.evp);
            if rsa.is_null() {
                panic!("Could not get RSA key for verification");
            }

            let rv = ffi::RSA_verify(openssl_hash_nid(hash),
                                     h.as_ptr(),
                                     h.len() as c_uint,
                                     s.as_ptr(),
                                     s.len() as c_uint,
                                     rsa);

            rv == 1 as c_int
        }
    }

    pub unsafe fn get_handle(&self) -> *mut ffi::EVP_PKEY {
        return self.evp;
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

impl Clone for PKey {
    fn clone(&self) -> Self {
        unsafe {
            rust_EVP_PKEY_clone(self.evp);
        }

        PKey::from_handle(self.evp, self.parts)
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
    fn test_public_key_from_pem() {
        let key_path = Path::new("test/key.pem.pub");
        let mut file = File::open(&key_path)
                           .ok()
                           .expect("Failed to open `test/key.pem.pub`");

        super::PKey::public_key_from_pem(&mut file).unwrap();
    }

    #[test]
    fn test_private_rsa_key_from_pem() {
        let key_path = Path::new("test/key.pem");
        let mut file = File::open(&key_path)
                            .ok()
                            .expect("Failed to open `test/key.pem`");

        super::PKey::private_rsa_key_from_pem(&mut file).unwrap();
    }

    #[test]
    fn test_public_rsa_key_from_pem() {
        let key_path = Path::new("test/key.pem.pub");
        let mut file = File::open(&key_path)
                            .ok()
                            .expect("Failed to open `test/key.pem.pub`");

        super::PKey::public_rsa_key_from_pem(&mut file).unwrap();
    }

    #[test]
    fn test_private_encrypt() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512);
        k1.load_pub(&k0.save_pub());
        let emsg = k0.private_encrypt(&msg);
        let dmsg = k1.public_decrypt(&emsg);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_public_encrypt() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512);
        k1.load_pub(&k0.save_pub());
        let emsg = k1.public_encrypt(&msg);
        let dmsg = k0.private_decrypt(&emsg);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_public_encrypt_pkcs() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
        k0.gen(512);
        k1.load_pub(&k0.save_pub());
        let emsg = k1.public_encrypt_with_padding(&msg, super::EncryptionPadding::PKCS1v15);
        let dmsg = k0.private_decrypt_with_padding(&emsg, super::EncryptionPadding::PKCS1v15);
        assert!(msg == dmsg);
    }

    #[test]
    fn test_sign() {
        let mut k0 = super::PKey::new();
        let mut k1 = super::PKey::new();
        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
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
        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];
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

    #[test]
    fn test_pem() {
        let key_path = Path::new("test/key.pem");
        let mut file = File::open(&key_path)
                           .ok()
                           .expect("Failed to open `test/key.pem`");

        let key = super::PKey::private_key_from_pem(&mut file).unwrap();

        let mut priv_key = Vec::new();
        let mut pub_key = Vec::new();

        key.write_pem(&mut priv_key).unwrap();
        key.write_pub_pem(&mut pub_key).unwrap();

        // As a super-simple verification, just check that the buffers contain
        // the `PRIVATE KEY` or `PUBLIC KEY` strings.
        assert!(priv_key.windows(11).any(|s| s == b"PRIVATE KEY"));
        assert!(pub_key.windows(10).any(|s| s == b"PUBLIC KEY"));
    }

    #[test]
    #[should_panic(expected = "Could not get RSA key for encryption")]
    fn test_nokey_encrypt() {
        let mut pkey = super::PKey::new();
        pkey.load_pub(&[]);
        pkey.encrypt(&[]);
    }

    #[test]
    #[should_panic(expected = "Could not get RSA key for decryption")]
    fn test_nokey_decrypt() {
        let mut pkey = super::PKey::new();
        pkey.load_priv(&[]);
        pkey.decrypt(&[]);
    }

    #[test]
    #[should_panic(expected = "Could not get RSA key for signing")]
    fn test_nokey_sign() {
        let mut pkey = super::PKey::new();
        pkey.load_priv(&[]);
        pkey.sign(&[]);
    }

    #[test]
    #[should_panic(expected = "Could not get RSA key for verification")]
    fn test_nokey_verify() {
        let mut pkey = super::PKey::new();
        pkey.load_pub(&[]);
        pkey.verify(&[], &[]);
    }
}
