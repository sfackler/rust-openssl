use libc::{c_void, c_char, c_int};
use std::ptr;
use std::mem;
use ffi;

use bio::{MemBio, MemBioSlice};
use crypto::dsa::DSA;
use crypto::rsa::RSA;
use error::ErrorStack;
use crypto::util::{CallbackState, invoke_passwd_cb};

pub struct PKey(*mut ffi::EVP_PKEY);

unsafe impl Send for PKey {}
unsafe impl Sync for PKey {}

/// Represents a public key, optionally with a private key attached.
impl PKey {
    /// Create a new `PKey` containing an RSA key.
    pub fn from_rsa(rsa: RSA) -> Result<PKey, ErrorStack> {
        unsafe {
            let evp = try_ssl_null!(ffi::EVP_PKEY_new());
            let pkey = PKey(evp);
            try_ssl!(ffi::EVP_PKEY_assign(pkey.0, ffi::EVP_PKEY_RSA, rsa.as_ptr() as *mut _));
            mem::forget(rsa);
            Ok(pkey)
        }
    }

    /// Create a new `PKey` containing a DSA key.
    pub fn from_dsa(dsa: DSA) -> Result<PKey, ErrorStack> {
        unsafe {
            let evp = try_ssl_null!(ffi::EVP_PKEY_new());
            let pkey = PKey(evp);
            try_ssl!(ffi::EVP_PKEY_assign(pkey.0, ffi::EVP_PKEY_DSA, dsa.as_ptr() as *mut _));
            mem::forget(dsa);
            Ok(pkey)
        }
    }

    /// Create a new `PKey` containing an HMAC key.
    pub fn hmac(key: &[u8]) -> Result<PKey, ErrorStack> {
        unsafe {
            assert!(key.len() <= c_int::max_value() as usize);
            let key = try_ssl_null!(ffi::EVP_PKEY_new_mac_key(ffi::EVP_PKEY_HMAC,
                                                              ptr::null_mut(),
                                                              key.as_ptr() as *const _,
                                                              key.len() as c_int));
            Ok(PKey(key))
        }
    }

    pub unsafe fn from_ptr(handle: *mut ffi::EVP_PKEY) -> PKey {
        PKey(handle)
    }

    /// Reads private key from PEM, takes ownership of handle
    pub fn private_key_from_pem(buf: &[u8]) -> Result<PKey, ErrorStack> {
        ffi::init();
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let evp = try_ssl_null!(ffi::PEM_read_bio_PrivateKey(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            Ok(PKey::from_ptr(evp))
        }
    }

    /// Read a private key from PEM, supplying a password callback to be invoked if the private key
    /// is encrypted.
    ///
    /// The callback will be passed the password buffer and should return the number of characters
    /// placed into the buffer.
    pub fn private_key_from_pem_cb<F>(buf: &[u8], pass_cb: F) -> Result<PKey, ErrorStack>
        where F: FnOnce(&mut [c_char]) -> usize
    {
        ffi::init();
        let mut cb = CallbackState::new(pass_cb);
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let evp = try_ssl_null!(ffi::PEM_read_bio_PrivateKey(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 Some(invoke_passwd_cb::<F>),
                                                                 &mut cb as *mut _ as *mut c_void));
            Ok(PKey::from_ptr(evp))
        }
    }

    /// Reads public key from PEM, takes ownership of handle
    pub fn public_key_from_pem(buf: &[u8]) -> Result<PKey, ErrorStack> {
        ffi::init();
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let evp = try_ssl_null!(ffi::PEM_read_bio_PUBKEY(mem_bio.as_ptr(),
                                                             ptr::null_mut(),
                                                             None,
                                                             ptr::null_mut()));
            Ok(PKey::from_ptr(evp))
        }
    }

    /// assign RSA key to this pkey
    pub fn set_rsa(&mut self, rsa: &RSA) -> Result<(), ErrorStack> {
        unsafe {
            // this needs to be a reference as the set1_RSA ups the reference count
            let rsa_ptr = rsa.as_ptr();
            try_ssl!(ffi::EVP_PKEY_set1_RSA(self.0, rsa_ptr));
            Ok(())
        }
    }

    /// Get a reference to the interal RSA key for direct access to the key components
    pub fn get_rsa(&self) -> Result<RSA, ErrorStack> {
        unsafe {
            let rsa = try_ssl_null!(ffi::EVP_PKEY_get1_RSA(self.0));
            // this is safe as the ffi increments a reference counter to the internal key
            Ok(RSA::from_ptr(rsa))
        }
    }

    /// Stores private key as a PEM
    // FIXME: also add password and encryption
    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        unsafe {
            try_ssl!(ffi::PEM_write_bio_PrivateKey(mem_bio.as_ptr(),
                                                   self.0,
                                                   ptr::null(),
                                                   ptr::null_mut(),
                                                   -1,
                                                   None,
                                                   ptr::null_mut()));

        }
        Ok(mem_bio.get_buf().to_owned())
    }

    /// Stores public key as a PEM
    pub fn public_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        unsafe { try_ssl!(ffi::PEM_write_bio_PUBKEY(mem_bio.as_ptr(), self.0)) }
        Ok(mem_bio.get_buf().to_owned())
    }

    pub fn as_ptr(&self) -> *mut ffi::EVP_PKEY {
        return self.0;
    }

    pub fn public_eq(&self, other: &PKey) -> bool {
        unsafe { ffi::EVP_PKEY_cmp(self.0, other.0) == 1 }
    }
}

impl Drop for PKey {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_PKEY_free(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_private_key_from_pem() {
        let key = include_bytes!("../../test/key.pem");
        super::PKey::private_key_from_pem(key).unwrap();
    }

    #[test]
    fn test_public_key_from_pem() {
        let key = include_bytes!("../../test/key.pem.pub");
        super::PKey::public_key_from_pem(key).unwrap();
    }

    #[test]
    fn test_pem() {
        let key = include_bytes!("../../test/key.pem");
        let key = super::PKey::private_key_from_pem(key).unwrap();

        let priv_key = key.private_key_to_pem().unwrap();
        let pub_key = key.public_key_to_pem().unwrap();

        // As a super-simple verification, just check that the buffers contain
        // the `PRIVATE KEY` or `PUBLIC KEY` strings.
        assert!(priv_key.windows(11).any(|s| s == b"PRIVATE KEY"));
        assert!(pub_key.windows(10).any(|s| s == b"PUBLIC KEY"));
    }
}
