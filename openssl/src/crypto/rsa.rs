use ffi;
use bn::BigNum;
use std::fmt;

pub struct RSA {
    pub rsa_obj : ffi::RSA
}

impl RSA {
    pub unsafe fn get_n(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.n).unwrap()
    }

    pub unsafe fn get_d(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.d).unwrap()
    }

    pub unsafe fn get_e(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.e).unwrap()
    }

    pub unsafe fn get_p(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.p).unwrap()
    }

    pub unsafe fn get_q(&self) -> BigNum {
        BigNum::new_from_ffi(self.rsa_obj.q).unwrap()
    }

    pub fn get_type(&self) -> &str {
        "rsa"
    }
}

impl fmt::Debug for RSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Currently no debug output. Sorry :(")
    }
}
