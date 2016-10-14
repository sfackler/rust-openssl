use ffi;
use std::fmt;
use error::ErrorStack;
use std::ptr;
use libc::{c_uint, c_int, c_char, c_void};

use bn::BigNumRef;
use bio::{MemBio, MemBioSlice};
use crypto::hash;
use HashTypeInternals;
use crypto::util::{CallbackState, invoke_passwd_cb};


/// Builder for upfront DSA parameter generateration
pub struct DSAParams(*mut ffi::DSA);

impl DSAParams {
    pub fn with_size(size: u32) -> Result<DSAParams, ErrorStack> {
        unsafe {
            // Wrap it so that if we panic we'll call the dtor
            let dsa = DSAParams(try_ssl_null!(ffi::DSA_new()));
            try_ssl!(ffi::DSA_generate_parameters_ex(dsa.0,
                                                     size as c_int,
                                                     ptr::null(),
                                                     0,
                                                     ptr::null_mut(),
                                                     ptr::null_mut(),
                                                     ptr::null_mut()));
            Ok(dsa)
        }
    }

    /// Generate a key pair from the initialized parameters
    pub fn generate(self) -> Result<DSA, ErrorStack> {
        unsafe {
            try_ssl!(ffi::DSA_generate_key(self.0));
            let dsa = DSA(self.0);
            ::std::mem::forget(self);
            Ok(dsa)
        }
    }
}

impl Drop for DSAParams {
    fn drop(&mut self) {
        unsafe {
            ffi::DSA_free(self.0);
        }
    }
}

pub struct DSA(*mut ffi::DSA);

impl Drop for DSA {
    fn drop(&mut self) {
        unsafe {
            ffi::DSA_free(self.0);
        }
    }
}

impl DSA {
    pub unsafe fn from_ptr(dsa: *mut ffi::DSA) -> DSA {
        DSA(dsa)
    }

    /// Generate a DSA key pair
    /// For more complicated key generation scenarios see the `DSAParams` type
    pub fn generate(size: u32) -> Result<DSA, ErrorStack> {
        let params = try!(DSAParams::with_size(size));
        params.generate()
    }

    /// Reads a DSA private key from PEM formatted data.
    pub fn private_key_from_pem(buf: &[u8]) -> Result<DSA, ErrorStack> {
        ffi::init();
        let mem_bio = try!(MemBioSlice::new(buf));

        unsafe {
            let dsa = try_ssl_null!(ffi::PEM_read_bio_DSAPrivateKey(mem_bio.as_ptr(),
                                                                    ptr::null_mut(),
                                                                    None,
                                                                    ptr::null_mut()));
            let dsa = DSA(dsa);
            assert!(dsa.has_private_key());
            Ok(dsa)
        }
    }

    /// Read a private key from PEM supplying a password callback to be invoked if the private key
    /// is encrypted.
    ///
    /// The callback will be passed the password buffer and should return the number of characters
    /// placed into the buffer.
    pub fn private_key_from_pem_cb<F>(buf: &[u8], pass_cb: F) -> Result<DSA, ErrorStack>
        where F: FnOnce(&mut [c_char]) -> usize
    {
        ffi::init();
        let mut cb = CallbackState::new(pass_cb);
        let mem_bio = try!(MemBioSlice::new(buf));

        unsafe {
            let cb_ptr = &mut cb as *mut _ as *mut c_void;
            let dsa = try_ssl_null!(ffi::PEM_read_bio_DSAPrivateKey(mem_bio.as_ptr(),
                                                                    ptr::null_mut(),
                                                                    Some(invoke_passwd_cb::<F>),
                                                                    cb_ptr));
            let dsa = DSA(dsa);
            assert!(dsa.has_private_key());
            Ok(dsa)
        }
    }

    /// Writes an DSA private key as unencrypted PEM formatted data
    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack>
    {
        assert!(self.has_private_key());
        let mem_bio = try!(MemBio::new());

        unsafe {
            try_ssl!(ffi::PEM_write_bio_DSAPrivateKey(mem_bio.as_ptr(), self.0,
                                              ptr::null(), ptr::null_mut(), 0,
                                              None, ptr::null_mut()))
        };

        Ok(mem_bio.get_buf().to_owned())
    }

    /// Reads an DSA public key from PEM formatted data.
    pub fn public_key_from_pem(buf: &[u8]) -> Result<DSA, ErrorStack>
    {
        ffi::init();

        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let dsa = try_ssl_null!(ffi::PEM_read_bio_DSA_PUBKEY(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            Ok(DSA(dsa))
        }
    }

    /// Writes an DSA public key as PEM formatted data
    pub fn public_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        unsafe { try_ssl!(ffi::PEM_write_bio_DSA_PUBKEY(mem_bio.as_ptr(), self.0)) };
        Ok(mem_bio.get_buf().to_owned())
    }

    pub fn size(&self) -> Option<u32> {
        if self.q().is_some() {
            unsafe { Some(ffi::DSA_size(self.0) as u32) }
        } else {
            None
        }
    }

    pub fn sign(&self, hash: hash::Type, message: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let k_len = self.size().expect("DSA missing a q") as c_uint;
        let mut sig = vec![0; k_len as usize];
        let mut sig_len = k_len;
        assert!(self.has_private_key());

        unsafe {
            try_ssl!(ffi::DSA_sign(hash.as_nid() as c_int,
                                   message.as_ptr(),
                                   message.len() as c_int,
                                   sig.as_mut_ptr(),
                                   &mut sig_len,
                                   self.0));
            sig.set_len(sig_len as usize);
            sig.shrink_to_fit();
            Ok(sig)
        }
    }

    pub fn verify(&self, hash: hash::Type, message: &[u8], sig: &[u8]) -> Result<bool, ErrorStack> {
        unsafe {
            let result = ffi::DSA_verify(hash.as_nid() as c_int,
                                         message.as_ptr(),
                                         message.len() as c_int,
                                         sig.as_ptr(),
                                         sig.len() as c_int,
                                         self.0);

            try_ssl_if!(result == -1);
            Ok(result == 1)
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::DSA {
        self.0
    }

    pub fn p<'a>(&'a self) -> Option<BigNumRef<'a>> {
        unsafe {
            let p = compat::pqg(self.0)[0];
            if p.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(p as *mut _))
            }
        }
    }

    pub fn q<'a>(&'a self) -> Option<BigNumRef<'a>> {
        unsafe {
            let q = compat::pqg(self.0)[1];
            if q.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(q as *mut _))
            }
        }
    }

    pub fn g<'a>(&'a self) -> Option<BigNumRef<'a>> {
        unsafe {
            let g = compat::pqg(self.0)[2];
            if g.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(g as *mut _))
            }
        }
    }

    pub fn has_public_key(&self) -> bool {
        unsafe { !compat::keys(self.0)[0].is_null() }
    }

    pub fn has_private_key(&self) -> bool {
        unsafe { !compat::keys(self.0)[1].is_null() }
    }
}

#[cfg(ossl110)]
mod compat {
    use std::ptr;
    use ffi::{self, BIGNUM, DSA};

    pub unsafe fn pqg(d: *const DSA) -> [*const BIGNUM; 3] {
        let (mut p, mut q, mut g) = (ptr::null(), ptr::null(), ptr::null());
        ffi::DSA_get0_pqg(d, &mut p, &mut q, &mut g);
        [p, q, g]
    }

    pub unsafe fn keys(d: *const DSA) -> [*const BIGNUM; 2] {
        let (mut pub_key, mut priv_key) = (ptr::null(), ptr::null());
        ffi::DSA_get0_key(d, &mut pub_key, &mut priv_key);
        [pub_key, priv_key]
    }
}

#[cfg(ossl10x)]
mod compat {
    use ffi::{BIGNUM, DSA};

    pub unsafe fn pqg(d: *const DSA) -> [*const BIGNUM; 3] {
        [(*d).p, (*d).q, (*d).g]
    }

    pub unsafe fn keys(d: *const DSA) -> [*const BIGNUM; 2] {
        [(*d).pub_key, (*d).priv_key]
    }
}

impl fmt::Debug for DSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DSA")
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;
    use libc::c_char;

    use super::*;
    use crypto::hash::*;

    #[test]
    pub fn test_generate() {
        let key = DSA::generate(1024).unwrap();

        key.public_key_to_pem().unwrap();
        key.private_key_to_pem().unwrap();

        let input: Vec<u8> = (0..25).cycle().take(1024).collect();

        let digest = {
            let mut sha = Hasher::new(Type::SHA1).unwrap();
            sha.write_all(&input).unwrap();
            sha.finish().unwrap()
        };

        let sig = key.sign(Type::SHA1, &digest).unwrap();
        let verified = key.verify(Type::SHA1, &digest, &sig).unwrap();
        assert!(verified);
    }

    #[test]
    pub fn test_sign_verify() {
        let input: Vec<u8> = (0..25).cycle().take(1024).collect();

        let private_key = {
            let key = include_bytes!("../../test/dsa.pem");
            DSA::private_key_from_pem(key).unwrap()
        };

        let public_key = {
            let key = include_bytes!("../../test/dsa.pem.pub");
            DSA::public_key_from_pem(key).unwrap()
        };

        let digest = {
            let mut sha = Hasher::new(Type::SHA1).unwrap();
            sha.write_all(&input).unwrap();
            sha.finish().unwrap()
        };

        let sig = private_key.sign(Type::SHA1, &digest).unwrap();
        let verified = public_key.verify(Type::SHA1, &digest, &sig).unwrap();
        assert!(verified);
    }

    #[test]
    pub fn test_sign_verify_fail() {
        let input: Vec<u8> = (0..25).cycle().take(128).collect();
        let private_key = {
            let key = include_bytes!("../../test/dsa.pem");
            DSA::private_key_from_pem(key).unwrap()
        };

        let public_key = {
            let key = include_bytes!("../../test/dsa.pem.pub");
            DSA::public_key_from_pem(key).unwrap()
        };

        let digest = {
            let mut sha = Hasher::new(Type::SHA1).unwrap();
            sha.write_all(&input).unwrap();
            sha.finish().unwrap()
        };

        let mut sig = private_key.sign(Type::SHA1, &digest).unwrap();
        // tamper with the sig this should cause a failure
        let len = sig.len();
        sig[len / 2] = 0;
        sig[len - 1] = 0;
        if let Ok(true) = public_key.verify(Type::SHA1, &digest, &sig) {
            panic!("Tampered with signatures should not verify!");
        }
    }

    #[test]
    pub fn test_password() {
        let mut password_queried = false;
        let key = include_bytes!("../../test/dsa-encrypted.pem");
        DSA::private_key_from_pem_cb(key, |password| {
            password_queried = true;
            password[0] = b'm' as c_char;
            password[1] = b'y' as c_char;
            password[2] = b'p' as c_char;
            password[3] = b'a' as c_char;
            password[4] = b's' as c_char;
            password[5] = b's' as c_char;
            6
        }).unwrap();

        assert!(password_queried);
    }
}
