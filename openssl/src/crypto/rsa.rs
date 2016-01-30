use ffi;
use std::fmt;
use ssl::error::{SslError, StreamError};
use std::ptr;
use std::io::{self, Read};

use bn::BigNum;
use bio::MemBio;

pub struct RSA(*mut ffi::RSA);

impl Drop for RSA {
    fn drop(&mut self) {
        unsafe {
            ffi::RSA_free(self.0);
        }
    }
}

impl RSA {
    /// Reads an RSA private key from PEM formatted data.
    pub fn private_key_from_pem<R>(reader: &mut R) -> Result<RSA, SslError>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

        unsafe {
            let rsa = try_ssl_null!(ffi::PEM_read_bio_RSAPrivateKey(mem_bio.get_handle(),
                                                                    ptr::null_mut(),
                                                                    None,
                                                                    ptr::null_mut()));
            Ok(RSA(rsa))
        }
    }

    /// Reads an RSA public key from PEM formatted data.
    pub fn public_key_from_pem<R>(reader: &mut R) -> Result<RSA, SslError>
    where R: Read
    {
        let mut mem_bio = try!(MemBio::new());
        try!(io::copy(reader, &mut mem_bio).map_err(StreamError));

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
    pub fn n(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).n)
        }
    }

    pub fn d(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).d)
        }
    }

    pub fn e(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).e)
        }
    }

    pub fn p(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi((*self.0).p)
        }
    }

    pub fn q(&self) -> Result<BigNum, SslError> {
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
