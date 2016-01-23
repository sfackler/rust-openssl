use ffi;
use bn::BigNum;
use std::fmt;
use ssl::error::SslError;

pub struct RSA {
    rsa_obj : ffi::RSA
}

impl RSA {
    // The following getters are unsafe, since BigNum::new_from_ffi fails upon null pointers
    pub fn n(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.n)
        }
    }

    pub fn d(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.d)
        }
    }

    pub fn e(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.e)
        }
    }

    pub fn p(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.p)
        }
    }

    pub fn q(&self) -> Result<BigNum, SslError> {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.q)
        }
    }
}

impl fmt::Debug for RSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RSA")
    }
}
