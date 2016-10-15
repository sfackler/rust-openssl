use ffi;
use std::fmt;
use std::ptr;
use std::mem;
use libc::{c_int, c_void, c_char};

use bn::{BigNum, BigNumRef};
use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use crypto::util::{CallbackState, invoke_passwd_cb};

/// Type of encryption padding to use.
#[derive(Copy, Clone)]
pub enum Padding {
    None,
    OAEP,
    PKCS1v15
}

impl Padding {
    fn openssl_padding_code(&self) -> c_int {
        match *self {
            Padding::None => ffi::RSA_NO_PADDING,
            Padding::OAEP => ffi::RSA_PKCS1_OAEP_PADDING,
            Padding::PKCS1v15 => ffi::RSA_PKCS1_PADDING
        }
    }
}

pub struct RSA(*mut ffi::RSA);

impl Drop for RSA {
    fn drop(&mut self) {
        unsafe {
            ffi::RSA_free(self.0);
        }
    }
}

impl RSA {
    /// only useful for associating the key material directly with the key, it's safer to use
    /// the supplied load and save methods for DER formatted keys.
    pub fn from_public_components(n: BigNum, e: BigNum) -> Result<RSA, ErrorStack> {
        unsafe {
            let rsa = RSA(try_ssl_null!(ffi::RSA_new()));
            try_ssl!(compat::set_key(rsa.0,
                                     n.as_ptr(),
                                     e.as_ptr(),
                                     ptr::null_mut()));
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
                                   -> Result<RSA, ErrorStack> {
        unsafe {
            let rsa = RSA(try_ssl_null!(ffi::RSA_new()));
            try_ssl!(compat::set_key(rsa.0, n.as_ptr(), e.as_ptr(), d.as_ptr()));
            mem::forget((n, e, d));
            try_ssl!(compat::set_factors(rsa.0, p.as_ptr(), q.as_ptr()));
            mem::forget((p, q));
            try_ssl!(compat::set_crt_params(rsa.0, dp.as_ptr(), dq.as_ptr(),
                                            qi.as_ptr()));
            mem::forget((dp, dq, qi));
            Ok(rsa)
        }
    }

    pub unsafe fn from_ptr(rsa: *mut ffi::RSA) -> RSA {
        RSA(rsa)
    }

    /// Generates a public/private key pair with the specified size.
    ///
    /// The public exponent will be 65537.
    pub fn generate(bits: u32) -> Result<RSA, ErrorStack> {
        unsafe {
            let rsa = try_ssl_null!(ffi::RSA_new());
            let rsa = RSA(rsa);
            let e = try!(BigNum::new_from(ffi::RSA_F4 as u32));

            try_ssl!(ffi::RSA_generate_key_ex(rsa.0, bits as c_int, e.as_ptr(), ptr::null_mut()));

            Ok(rsa)
        }
    }

    /// Reads an RSA private key from PEM formatted data.
    pub fn private_key_from_pem(buf: &[u8]) -> Result<RSA, ErrorStack> {
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.as_ptr(),
                                                                    ptr::null_mut(),
                                                                    None,
                                                                    ptr::null_mut()));
            Ok(RSA(rsa))
        }
    }

    /// Reads an RSA private key from PEM formatted data and supplies a password callback.
    pub fn private_key_from_pem_cb<F>(buf: &[u8], pass_cb: F) -> Result<RSA, ErrorStack>
        where F: FnOnce(&mut [c_char]) -> usize
    {
        let mut cb = CallbackState::new(pass_cb);
        let mem_bio = try!(MemBioSlice::new(buf));

        unsafe {
            let cb_ptr = &mut cb as *mut _ as *mut c_void;
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.as_ptr(),
                                                                    ptr::null_mut(),
                                                                    Some(invoke_passwd_cb::<F>),
                                                                    cb_ptr));

            Ok(RSA(rsa))
        }
    }

    /// Reads an RSA public key from PEM formatted data.
    pub fn public_key_from_pem(buf: &[u8]) -> Result<RSA, ErrorStack> {
        let mem_bio = try!(MemBioSlice::new(buf));
        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSA_PUBKEY(mem_bio.as_ptr(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            Ok(RSA(rsa))
        }
    }

    /// Writes an RSA private key as unencrypted PEM formatted data
    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());

        unsafe {
            try_ssl!(ffi::PEM_write_bio_RSAPrivateKey(mem_bio.as_ptr(),
                                             self.0,
                                             ptr::null(),
                                             ptr::null_mut(),
                                             0,
                                             None,
                                             ptr::null_mut()));
        }
        Ok(mem_bio.get_buf().to_owned())
    }

    /// Writes an RSA public key as PEM formatted data
    pub fn public_key_to_pem(&self) -> Result<Vec<u8>, ErrorStack> {
        let mem_bio = try!(MemBio::new());

        unsafe {
            try_ssl!(ffi::PEM_write_bio_RSA_PUBKEY(mem_bio.as_ptr(), self.0))
        };

        Ok(mem_bio.get_buf().to_owned())
    }

    pub fn size(&self) -> Option<u32> {
        if self.n().is_some() {
            unsafe { Some(ffi::RSA_size(self.0) as u32) }
        } else {
            None
        }
    }

    /**
     * Decrypts data with the private key, using provided padding, returning the decrypted data.
     */
    pub fn private_decrypt(&self, from: &[u8], padding: Padding) -> Result<Vec<u8>, ErrorStack> {
        assert!(self.d().is_some(), "private components missing");
        let k_len = self.size().expect("RSA missing an n");
        let mut to: Vec<u8> = vec![0; k_len as usize];

        unsafe {
            let enc_len = try_ssl_returns_size!(ffi::RSA_private_decrypt(from.len() as i32,
                                   from.as_ptr(),
                                   to.as_mut_ptr(),
                                   self.0,
                                   padding.openssl_padding_code()));
           to.truncate(enc_len as usize);
           Ok(to)
        }
    }

    /**
     * Encrypts data with the private key, using provided padding, returning the encrypted data.
     */
    pub fn private_encrypt(&self, from: &[u8], padding: Padding) -> Result<Vec<u8>, ErrorStack> {
        assert!(self.d().is_some(), "private components missing");
        let k_len = self.size().expect("RSA missing an n");
        let mut to:Vec<u8> = vec![0; k_len as usize];

        unsafe {
            let enc_len = try_ssl_returns_size!(ffi::RSA_private_encrypt(from.len() as c_int,
                                   from.as_ptr(),
                                   to.as_mut_ptr(),
                                   self.0,
                                   padding.openssl_padding_code()));
           assert!(enc_len as u32 == k_len);

           Ok(to)
        }
    }

    /**
     * Decrypts data with the public key, using provided padding, returning the decrypted data.
     */
    pub fn public_decrypt(&self, from: &[u8], padding: Padding) -> Result<Vec<u8>, ErrorStack> {
        let k_len = self.size().expect("RSA missing an n");
        let mut to: Vec<u8> = vec![0; k_len as usize];

        unsafe {
            let enc_len = try_ssl_returns_size!(ffi::RSA_public_decrypt(from.len() as i32,
                                   from.as_ptr(),
                                   to.as_mut_ptr(),
                                   self.0,
                                   padding.openssl_padding_code()));
           to.truncate(enc_len as usize);
           Ok(to)
        }
    }

    /**
     * Encrypts data with the public key, using provided padding, returning the encrypted data.
     */
    pub fn public_encrypt(&self, from: &[u8], padding: Padding) -> Result<Vec<u8>, ErrorStack> {
        let k_len = self.size().expect("RSA missing an n");
        let mut to:Vec<u8> = vec![0; k_len as usize];

        unsafe {
            let enc_len = try_ssl_returns_size!(ffi::RSA_public_encrypt(from.len() as c_int,
                                   from.as_ptr(),
                                   to.as_mut_ptr(),
                                   self.0,
                                   padding.openssl_padding_code()));
           assert!(enc_len as u32 == k_len);

           Ok(to)
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::RSA {
        self.0
    }

    pub fn n<'a>(&'a self) -> Option<BigNumRef<'a>> {
        unsafe {
            let n = compat::key(self.0)[0];
            if n.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(n as *mut _))
            }
        }
    }

    pub fn d<'a>(&self) -> Option<BigNumRef<'a>> {
        unsafe {
            let d = compat::key(self.0)[2];
            if d.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(d as *mut _))
            }
        }
    }

    pub fn e<'a>(&'a self) -> Option<BigNumRef<'a>> {
        unsafe {
            let e = compat::key(self.0)[1];
            if e.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(e as *mut _))
            }
        }
    }

    pub fn p<'a>(&'a self) -> Option<BigNumRef<'a>> {
        unsafe {
            let p = compat::factors(self.0)[0];
            if p.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(p as *mut _))
            }
        }
    }

    pub fn q<'a>(&'a self) -> Option<BigNumRef<'a>> {
        unsafe {
            let q = compat::factors(self.0)[1];
            if q.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(q as *mut _))
            }
        }
    }
}

impl fmt::Debug for RSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RSA")
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

    pub unsafe fn set_key(r: *mut RSA,
                          n: *mut BIGNUM,
                          e: *mut BIGNUM,
                          d: *mut BIGNUM) -> c_int {
        ffi::RSA_set0_key(r, n, e, d)
    }

    pub unsafe fn set_factors(r: *mut RSA,
                              p: *mut BIGNUM,
                              q: *mut BIGNUM) -> c_int {
        ffi::RSA_set0_factors(r, p, q)
    }

    pub unsafe fn set_crt_params(r: *mut RSA,
                                 dmp1: *mut BIGNUM,
                                 dmq1: *mut BIGNUM,
                                 iqmp: *mut BIGNUM) -> c_int {
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

    pub unsafe fn set_key(r: *mut RSA,
                          n: *mut BIGNUM,
                          e: *mut BIGNUM,
                          d: *mut BIGNUM) -> c_int {
        (*r).n = n;
        (*r).e = e;
        (*r).d = d;
        1 // TODO: is this right? should it be 0? what's success?
    }

    pub unsafe fn set_factors(r: *mut RSA,
                              p: *mut BIGNUM,
                              q: *mut BIGNUM) -> c_int {
        (*r).p = p;
        (*r).q = q;
        1 // TODO: is this right? should it be 0? what's success?
    }

    pub unsafe fn set_crt_params(r: *mut RSA,
                                 dmp1: *mut BIGNUM,
                                 dmq1: *mut BIGNUM,
                                 iqmp: *mut BIGNUM) -> c_int {
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
        let key = include_bytes!("../../test/rsa-encrypted.pem");
        RSA::private_key_from_pem_cb(key, |password| {
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

    #[test]
    pub fn test_public_encrypt_private_decrypt_with_padding() {
        let key = include_bytes!("../../test/rsa.pem.pub");
        let public_key = RSA::public_key_from_pem(key).unwrap();

        let original_data: Vec<u8> = "This is test".to_string().into_bytes();
        let result = public_key.public_encrypt(&original_data, Padding::PKCS1v15).unwrap();

        assert_eq!(result.len(), 256);

        let pkey = include_bytes!("../../test/rsa.pem");
        let private_key = RSA::private_key_from_pem(pkey).unwrap();
        let dec_result = private_key.private_decrypt(&result, Padding::PKCS1v15).unwrap();

       assert_eq!(dec_result, original_data);
    }

    #[test]
   fn test_private_encrypt() {
       let k0 = super::RSA::generate(512).unwrap();
       let k0pkey = k0.public_key_to_pem().unwrap();
       let k1 = super::RSA::public_key_from_pem(&k0pkey).unwrap();

       let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);

       let emsg = k0.private_encrypt(&msg, Padding::PKCS1v15).unwrap();
       let dmsg = k1.public_decrypt(&emsg, Padding::PKCS1v15).unwrap();
       assert!(msg == dmsg);
   }

   #[test]
   fn test_public_encrypt() {
       let k0 = super::RSA::generate(512).unwrap();
       let k0pkey = k0.public_key_to_pem().unwrap();
       let k1 = super::RSA::public_key_from_pem(&k0pkey).unwrap();

       let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);

       let emsg = k1.public_encrypt(&msg, Padding::OAEP).unwrap();
       let dmsg = k0.private_decrypt(&emsg, Padding::OAEP).unwrap();
       assert!(msg == dmsg);
   }

   #[test]
   fn test_public_encrypt_pkcs() {
       let k0 = super::RSA::generate(512).unwrap();
       let k0pkey = k0.public_key_to_pem().unwrap();
       let k1 = super::RSA::public_key_from_pem(&k0pkey).unwrap();

       let msg = vec!(0xdeu8, 0xadu8, 0xd0u8, 0x0du8);

       let emsg = k1.public_encrypt(&msg, super::Padding::PKCS1v15).unwrap();
       let dmsg = k0.private_decrypt(&emsg, super::Padding::PKCS1v15).unwrap();
       assert!(msg == dmsg);
   }

}
