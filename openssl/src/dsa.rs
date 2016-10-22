use ffi;
use std::fmt;
use error::ErrorStack;
use std::ptr;
use libc::{c_int, c_char, c_void};

use {cvt, cvt_p};
use bn::BigNumRef;
use bio::{MemBio, MemBioSlice};
use util::{CallbackState, invoke_passwd_cb};

/// Builder for upfront DSA parameter generation
pub struct DsaParams(*mut ffi::DSA);

impl DsaParams {
    pub fn with_size(size: u32) -> Result<DsaParams, ErrorStack> {
        unsafe {
            let dsa = DsaParams(try!(cvt_p(ffi::DSA_new())));
            try!(cvt(ffi::DSA_generate_parameters_ex(dsa.0,
                                                     size as c_int,
                                                     ptr::null(),
                                                     0,
                                                     ptr::null_mut(),
                                                     ptr::null_mut(),
                                                     ptr::null_mut())));
            Ok(dsa)
        }
    }

    /// Generate a key pair from the initialized parameters
    pub fn generate(self) -> Result<Dsa, ErrorStack> {
        unsafe {
            try!(cvt(ffi::DSA_generate_key(self.0)));
            let dsa = Dsa(self.0);
            ::std::mem::forget(self);
            Ok(dsa)
        }
    }
}

impl Drop for DsaParams {
    fn drop(&mut self) {
        unsafe {
            ffi::DSA_free(self.0);
        }
    }
}

pub struct Dsa(*mut ffi::DSA);

impl Drop for Dsa {
    fn drop(&mut self) {
        unsafe {
            ffi::DSA_free(self.0);
        }
    }
}

impl Dsa {
    pub unsafe fn from_ptr(dsa: *mut ffi::DSA) -> Dsa {
        Dsa(dsa)
    }

    /// Generate a DSA key pair
    /// For more complicated key generation scenarios see the `DSAParams` type
    pub fn generate(size: u32) -> Result<Dsa, ErrorStack> {
        let params = try!(DsaParams::with_size(size));
        params.generate()
    }

    /// Reads a DSA private key from PEM formatted data.
    pub fn private_key_from_pem(buf: &[u8]) -> Result<Dsa, ErrorStack> {
        ffi::init();
        let mem_bio = try!(MemBioSlice::new(buf));

        unsafe {
            let dsa = try!(cvt_p(ffi::PEM_read_bio_DSAPrivateKey(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut())));
            Ok(Dsa(dsa))
        }
    }

    /// Read a private key from PEM supplying a password callback to be invoked if the private key
    /// is encrypted.
    ///
    /// The callback will be passed the password buffer and should return the number of characters
    /// placed into the buffer.
    pub fn private_key_from_pem_cb<F>(buf: &[u8], pass_cb: F) -> Result<Dsa, ErrorStack>
        where F: FnOnce(&mut [c_char]) -> usize
    {
        ffi::init();
        let mut cb = CallbackState::new(pass_cb);
        let mem_bio = try!(MemBioSlice::new(buf));

        unsafe {
            let cb_ptr = &mut cb as *mut _ as *mut c_void;
            let dsa = try!(cvt_p(ffi::PEM_read_bio_DSAPrivateKey(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 Some(invoke_passwd_cb::<F>),
                                                                 cb_ptr)));
            Ok(Dsa(dsa))
        }
    }

    /// Writes an DSA private key as unencrypted PEM formatted data
    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack>
    {
        assert!(self.has_private_key());
        let mem_bio = try!(MemBio::new());

        unsafe {
            try!(cvt(ffi::PEM_write_bio_DSAPrivateKey(mem_bio.as_ptr(), self.0,
                                                      ptr::null(), ptr::null_mut(), 0,
                                                      None, ptr::null_mut())))
        };

        Ok(mem_bio.get_buf().to_owned())
    }

    /// Reads an DSA public key from PEM formatted data.
    pub fn public_key_from_pem(buf: &[u8]) -> Result<Dsa, ErrorStack>
    {
        ffi::init();

        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let dsa = try!(cvt_p(ffi::PEM_read_bio_DSA_PUBKEY(mem_bio.as_ptr(),
                                                              ptr::null_mut(),
                                                              None,
                                                              ptr::null_mut())));
            Ok(Dsa(dsa))
        }
    }

    /// Writes an DSA public key as PEM formatted data
    pub fn public_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());
        unsafe {
            try!(cvt(ffi::PEM_write_bio_DSA_PUBKEY(mem_bio.as_ptr(), self.0)));
        }
        Ok(mem_bio.get_buf().to_owned())
    }

    pub fn size(&self) -> Option<u32> {
        if self.q().is_some() {
            unsafe { Some(ffi::DSA_size(self.0) as u32) }
        } else {
            None
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::DSA {
        self.0
    }

    pub fn p(&self) -> Option<&BigNumRef> {
        unsafe {
            let p = compat::pqg(self.0)[0];
            if p.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(p as *mut _))
            }
        }
    }

    pub fn q(&self) -> Option<&BigNumRef> {
        unsafe {
            let q = compat::pqg(self.0)[1];
            if q.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(q as *mut _))
            }
        }
    }

    pub fn g(&self) -> Option<&BigNumRef> {
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

impl fmt::Debug for Dsa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DSA")
    }
}

#[cfg(test)]
mod test {
    use libc::c_char;

    use super::*;

    #[test]
    pub fn test_generate() {
        Dsa::generate(1024).unwrap();
    }

    #[test]
    pub fn test_password() {
        let mut password_queried = false;
        let key = include_bytes!("../test/dsa-encrypted.pem");
        Dsa::private_key_from_pem_cb(key, |password| {
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
