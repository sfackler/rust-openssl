use ffi;
use std::fmt;
use std::ptr;
use std::mem;
use libc::{c_int, c_void, c_char};

use {cvt, cvt_p, cvt_n};
use bn::{BigNum, BigNumRef};
use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use util::{CallbackState, invoke_passwd_cb};
use types::OpenSslTypeRef;

/// Type of encryption padding to use.
#[derive(Copy, Clone)]
pub struct Padding(c_int);

pub const NO_PADDING: Padding = Padding(ffi::RSA_NO_PADDING);
pub const PKCS1_PADDING: Padding = Padding(ffi::RSA_PKCS1_PADDING);
pub const PKCS1_OAEP_PADDING: Padding = Padding(ffi::RSA_PKCS1_OAEP_PADDING);

type_!(Rsa, RsaRef, ffi::RSA, ffi::RSA_free);

impl RsaRef {
    /// Writes an RSA private key as unencrypted PEM formatted data
    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());

        unsafe {
            try!(cvt(ffi::PEM_write_bio_RSAPrivateKey(mem_bio.as_ptr(),
                                                      self.as_ptr(),
                                                      ptr::null(),
                                                      ptr::null_mut(),
                                                      0,
                                                      None,
                                                      ptr::null_mut())));
        }
        Ok(mem_bio.get_buf().to_owned())
    }

    /// Writes an RSA public key as PEM formatted data
    pub fn public_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());

        unsafe {
            try!(cvt(ffi::PEM_write_bio_RSA_PUBKEY(mem_bio.as_ptr(), self.as_ptr())));
        }

        Ok(mem_bio.get_buf().to_owned())
    }

    pub fn size(&self) -> usize {
        unsafe {
            assert!(self.n().is_some());

            ffi::RSA_size(self.as_ptr()) as usize
        }
    }

    /// Decrypts data using the private key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    pub fn private_decrypt(&self,
                           from: &[u8],
                           to: &mut [u8],
                           padding: Padding)
                           -> Result<usize, ErrorStack> {
        assert!(self.d().is_some(), "private components missing");
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size());

        unsafe {
            let len = try!(cvt_n(ffi::RSA_private_decrypt(from.len() as c_int,
                                                          from.as_ptr(),
                                                          to.as_mut_ptr(),
                                                          self.as_ptr(),
                                                          padding.0)));
            Ok(len as usize)
        }
    }

    /// Encrypts data using the private key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    pub fn private_encrypt(&self,
                           from: &[u8],
                           to: &mut [u8],
                           padding: Padding)
                           -> Result<usize, ErrorStack> {
        assert!(self.d().is_some(), "private components missing");
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size());

        unsafe {
            let len = try!(cvt_n(ffi::RSA_private_encrypt(from.len() as c_int,
                                                          from.as_ptr(),
                                                          to.as_mut_ptr(),
                                                          self.as_ptr(),
                                                          padding.0)));
            Ok(len as usize)
        }
    }

    /// Decrypts data using the public key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    pub fn public_decrypt(&self,
                          from: &[u8],
                          to: &mut [u8],
                          padding: Padding)
                          -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size());

        unsafe {
            let len = try!(cvt_n(ffi::RSA_public_decrypt(from.len() as c_int,
                                                         from.as_ptr(),
                                                         to.as_mut_ptr(),
                                                         self.as_ptr(),
                                                         padding.0)));
            Ok(len as usize)
        }
    }

    /// Encrypts data using the private key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    pub fn public_encrypt(&self,
                          from: &[u8],
                          to: &mut [u8],
                          padding: Padding)
                          -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::max_value() as usize);
        assert!(to.len() >= self.size());

        unsafe {
            let len = try!(cvt_n(ffi::RSA_public_encrypt(from.len() as c_int,
                                                         from.as_ptr(),
                                                         to.as_mut_ptr(),
                                                         self.as_ptr(),
                                                         padding.0)));
            Ok(len as usize)
        }
    }

    pub fn n(&self) -> Option<&BigNumRef> {
        unsafe {
            let n = compat::key(self.as_ptr())[0];
            if n.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(n as *mut _))
            }
        }
    }

    pub fn d(&self) -> Option<&BigNumRef> {
        unsafe {
            let d = compat::key(self.as_ptr())[2];
            if d.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(d as *mut _))
            }
        }
    }

    pub fn e(&self) -> Option<&BigNumRef> {
        unsafe {
            let e = compat::key(self.as_ptr())[1];
            if e.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(e as *mut _))
            }
        }
    }

    pub fn p(&self) -> Option<&BigNumRef> {
        unsafe {
            let p = compat::factors(self.as_ptr())[0];
            if p.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(p as *mut _))
            }
        }
    }

    pub fn q(&self) -> Option<&BigNumRef> {
        unsafe {
            let q = compat::factors(self.as_ptr())[1];
            if q.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(q as *mut _))
            }
        }
    }
}

impl Rsa {
    /// only useful for associating the key material directly with the key, it's safer to use
    /// the supplied load and save methods for DER formatted keys.
    pub fn from_public_components(n: BigNum, e: BigNum) -> Result<Rsa, ErrorStack> {
        unsafe {
            let rsa = Rsa(try!(cvt_p(ffi::RSA_new())));
            try!(cvt(compat::set_key(rsa.0,
                                     n.as_ptr(),
                                     e.as_ptr(),
                                     ptr::null_mut())));
            mem::forget((n, e));
            Ok(rsa)
        }
    }

    pub fn from_private_components(n: BigNum,
                                   e: BigNum,
                                   d: BigNum,
                                   p: BigNum,
                                   q: BigNum,
                                   dp: BigNum,
                                   dq: BigNum,
                                   qi: BigNum)
                                   -> Result<Rsa, ErrorStack> {
        unsafe {
            let rsa = Rsa(try!(cvt_p(ffi::RSA_new())));
            try!(cvt(compat::set_key(rsa.0, n.as_ptr(), e.as_ptr(), d.as_ptr())));
            mem::forget((n, e, d));
            try!(cvt(compat::set_factors(rsa.0, p.as_ptr(), q.as_ptr())));
            mem::forget((p, q));
            try!(cvt(compat::set_crt_params(rsa.0, dp.as_ptr(), dq.as_ptr(),
                                            qi.as_ptr())));
            mem::forget((dp, dq, qi));
            Ok(rsa)
        }
    }

    /// Generates a public/private key pair with the specified size.
    ///
    /// The public exponent will be 65537.
    pub fn generate(bits: u32) -> Result<Rsa, ErrorStack> {
        unsafe {
            let rsa = Rsa(try!(cvt_p(ffi::RSA_new())));
            let e = try!(BigNum::from_u32(ffi::RSA_F4 as u32));
            try!(cvt(ffi::RSA_generate_key_ex(rsa.0, bits as c_int, e.as_ptr(), ptr::null_mut())));
            Ok(rsa)
        }
    }

    /// Reads an RSA private key from PEM formatted data.
    pub fn private_key_from_pem(buf: &[u8]) -> Result<Rsa, ErrorStack> {
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let rsa = try!(cvt_p(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut())));
            Ok(Rsa(rsa))
        }
    }

    /// Reads an RSA private key from PEM formatted data and supplies a password callback.
    pub fn private_key_from_pem_cb<F>(buf: &[u8], pass_cb: F) -> Result<Rsa, ErrorStack>
        where F: FnOnce(&mut [c_char]) -> usize
    {
        let mut cb = CallbackState::new(pass_cb);
        let mem_bio = try!(MemBioSlice::new(buf));

        unsafe {
            let cb_ptr = &mut cb as *mut _ as *mut c_void;
            let rsa = try!(cvt_p(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 Some(invoke_passwd_cb::<F>),
                                                                 cb_ptr)));
            Ok(Rsa(rsa))
        }
    }

    /// Reads an RSA public key from PEM formatted data.
    pub fn public_key_from_pem(buf: &[u8]) -> Result<Rsa, ErrorStack> {
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let rsa = try!(cvt_p(ffi::PEM_read_bio_RSA_PUBKEY(mem_bio.as_ptr(),
                                                              ptr::null_mut(),
                                                              None,
                                                              ptr::null_mut())));
            Ok(Rsa(rsa))
        }
    }
}

impl fmt::Debug for Rsa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rsa")
    }
}

#[cfg(ossl110)]
mod compat {
    use std::ptr;

    use ffi::{self, BIGNUM, RSA};
    use libc::c_int;

    pub unsafe fn key(r: *const RSA) -> [*const BIGNUM; 3] {
        let (mut n, mut e, mut d) = (ptr::null(), ptr::null(), ptr::null());
        ffi::RSA_get0_key(r, &mut n, &mut e, &mut d);
        [n, e, d]
    }

    pub unsafe fn factors(r: *const RSA) -> [*const BIGNUM; 2] {
        let (mut p, mut q) = (ptr::null(), ptr::null());
        ffi::RSA_get0_factors(r, &mut p, &mut q);
        [p, q]
    }

    pub unsafe fn set_key(r: *mut RSA, n: *mut BIGNUM, e: *mut BIGNUM, d: *mut BIGNUM) -> c_int {
        ffi::RSA_set0_key(r, n, e, d)
    }

    pub unsafe fn set_factors(r: *mut RSA, p: *mut BIGNUM, q: *mut BIGNUM) -> c_int {
        ffi::RSA_set0_factors(r, p, q)
    }

    pub unsafe fn set_crt_params(r: *mut RSA,
                                 dmp1: *mut BIGNUM,
                                 dmq1: *mut BIGNUM,
                                 iqmp: *mut BIGNUM)
                                 -> c_int {
        ffi::RSA_set0_crt_params(r, dmp1, dmq1, iqmp)
    }
}

#[cfg(ossl10x)]
mod compat {
    use libc::c_int;
    use ffi::{BIGNUM, RSA};

    pub unsafe fn key(r: *const RSA) -> [*const BIGNUM; 3] {
        [(*r).n, (*r).e, (*r).d]
    }

    pub unsafe fn factors(r: *const RSA) -> [*const BIGNUM; 2] {
        [(*r).p, (*r).q]
    }

    pub unsafe fn set_key(r: *mut RSA, n: *mut BIGNUM, e: *mut BIGNUM, d: *mut BIGNUM) -> c_int {
        (*r).n = n;
        (*r).e = e;
        (*r).d = d;
        1 // TODO: is this right? should it be 0? what's success?
    }

    pub unsafe fn set_factors(r: *mut RSA, p: *mut BIGNUM, q: *mut BIGNUM) -> c_int {
        (*r).p = p;
        (*r).q = q;
        1 // TODO: is this right? should it be 0? what's success?
    }

    pub unsafe fn set_crt_params(r: *mut RSA,
                                 dmp1: *mut BIGNUM,
                                 dmq1: *mut BIGNUM,
                                 iqmp: *mut BIGNUM)
                                 -> c_int {
        (*r).dmp1 = dmp1;
        (*r).dmq1 = dmq1;
        (*r).iqmp = iqmp;
        1 // TODO: is this right? should it be 0? what's success?
    }
}


#[cfg(test)]
mod test {
    use libc::c_char;

    use super::*;

    #[test]
    pub fn test_password() {
        let mut password_queried = false;
        let key = include_bytes!("../test/rsa-encrypted.pem");
        Rsa::private_key_from_pem_cb(key, |password| {
                password_queried = true;
                password[0] = b'm' as c_char;
                password[1] = b'y' as c_char;
                password[2] = b'p' as c_char;
                password[3] = b'a' as c_char;
                password[4] = b's' as c_char;
                password[5] = b's' as c_char;
                6
            })
            .unwrap();

        assert!(password_queried);
    }

    #[test]
    pub fn test_public_encrypt_private_decrypt_with_padding() {
        let key = include_bytes!("../test/rsa.pem.pub");
        let public_key = Rsa::public_key_from_pem(key).unwrap();

        let mut result = vec![0; public_key.size()];
        let original_data = b"This is test";
        let len = public_key.public_encrypt(original_data, &mut result, PKCS1_PADDING).unwrap();
        assert_eq!(len, 256);

        let pkey = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(pkey).unwrap();
        let mut dec_result = vec![0; private_key.size()];
        let len = private_key.private_decrypt(&result, &mut dec_result, PKCS1_PADDING).unwrap();

        assert_eq!(&dec_result[..len], original_data);
    }

    #[test]
    fn test_private_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.public_key_to_pem().unwrap();
        let k1 = super::Rsa::public_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size()];
        k0.private_encrypt(&msg, &mut emesg, PKCS1_PADDING).unwrap();
        let mut dmesg = vec![0; k1.size()];
        let len = k1.public_decrypt(&emesg, &mut dmesg, PKCS1_PADDING).unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

    #[test]
    fn test_public_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.private_key_to_pem().unwrap();
        let k1 = super::Rsa::private_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size()];
        k0.public_encrypt(&msg, &mut emesg, PKCS1_PADDING).unwrap();
        let mut dmesg = vec![0; k1.size()];
        let len = k1.private_decrypt(&emesg, &mut dmesg, PKCS1_PADDING).unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

}
