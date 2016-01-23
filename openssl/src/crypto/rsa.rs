use ffi;
use bn::BigNum;
use std::fmt;

pub struct RSA {
    rsa_obj : ffi::RSA
}

impl RSA {
    // The following getters are unsafe, since BigNum::new_from_ffi fails upon null pointers
    pub fn n(&self) -> BigNum {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.n).unwrap()
        }
    }

    pub fn d(&self) -> BigNum {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.d).unwrap()
        }
    }

    pub fn e(&self) -> BigNum {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.e).unwrap()
        }
    }

    pub fn p(&self) -> BigNum {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.p).unwrap()
        }
    }

    pub fn q(&self) -> BigNum {
        unsafe {
            BigNum::new_from_ffi(self.rsa_obj.q).unwrap()
        }
    }
}

impl fmt::Debug for RSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RSA")
    }
}
