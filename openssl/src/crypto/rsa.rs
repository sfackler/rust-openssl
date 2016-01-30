use ffi;
use std::fmt;
use std::ptr;
use std::io::{self, Read};

use bn::BigNum;
use bio::MemBio;
use error::ErrorStack;

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
            let rsa = try_ssl_null!(ffi::RSA_new());
            (*rsa).n = n.into_raw();
            (*rsa).e = e.into_raw();
            Ok(RSA(rsa))
        }
    }

    /// the caller should assert that the rsa pointer is valid.
    pub unsafe fn from_raw(rsa: *mut ffi::RSA) -> RSA {
        RSA(rsa)
    }

    /// Reads an RSA private key from PEM formatted data.
    pub fn private_key_from_pem<R>(reader: &mut R) -> io::Result<RSA>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio));

        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.get_handle(),
                                                                    ptr::null_mut(),
                                                                    None,
                                                                    ptr::null_mut()));
            Ok(RSA(rsa))
        }
    }

    /// Reads an RSA public key from PEM formatted data.
    pub fn public_key_from_pem<R>(reader: &mut R) -> io::Result<RSA>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio));

        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSA_PUBKEY(mem_bio.get_handle(),
                                                                 ptr::null_mut(),
                                                                 None,
                                                                 ptr::null_mut()));
            Ok(RSA(rsa))
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::RSA {
        self.0
    }

    // The following getters are unsafe, since BigNum::new_from_ffi fails upon null pointers
    pub fn n(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            BigNum::new_from_ffi((*self.0).n)
        }
    }

    pub fn has_n(&self) -> bool {
        unsafe {
            !(*self.0).n.is_null()
        }
    }

    pub fn d(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            BigNum::new_from_ffi((*self.0).d)
        }
    }

    pub fn e(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            BigNum::new_from_ffi((*self.0).e)
        }
    }

    pub fn has_e(&self) -> bool {
        unsafe {
            !(*self.0).e.is_null()
        }
    }

    pub fn p(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            BigNum::new_from_ffi((*self.0).p)
        }
    }

    pub fn q(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            BigNum::new_from_ffi((*self.0).q)
        }
    }
}

impl fmt::Debug for RSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RSA")
    }
}
