use ffi;
use bn::BigNum;
use std::fmt;

pub struct RSA {
    rsa_obj : ffi::RSA
}

impl RSA {
    pub unsafe fn n(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.n).unwrap()
    }

    pub unsafe fn d(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.d).unwrap()
    }

    pub unsafe fn e(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.e).unwrap()
    }

    pub unsafe fn p(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.p).unwrap()
    }

    pub unsafe fn q(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.q).unwrap()
    }
}

impl fmt::Debug for RSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Currently no debug output. Sorry :(")
    }
}
