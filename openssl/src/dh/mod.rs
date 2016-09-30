use ffi;
use error::ErrorStack;
use bio::MemBioSlice;
use std::ptr;

use bn::BigNum;
use std::mem;

pub struct DH(*mut ffi::DH);

impl DH {
    pub fn from_params(p: BigNum, g: BigNum, q: BigNum) -> Result<DH, ErrorStack> {
        unsafe {
            let dh = DH(try_ssl_null!(ffi::DH_new()));
            try_ssl!(compat::DH_set0_pqg(dh.0,
                                         p.as_ptr(),
                                         q.as_ptr(),
                                         g.as_ptr()));
            mem::forget((p, g, q));
            Ok(dh)
        }
    }

    pub fn from_pem(buf: &[u8]) -> Result<DH, ErrorStack> {
        let mem_bio = try!(MemBioSlice::new(buf));
        let dh = unsafe {
            ffi::PEM_read_bio_DHparams(mem_bio.as_ptr(), ptr::null_mut(), None, ptr::null_mut())
        };
        try_ssl_null!(dh);
        Ok(DH(dh))
    }

    #[cfg(all(feature = "rfc5114", not(ossl101)))]
    pub fn get_1024_160() -> Result<DH, ErrorStack> {
        let dh = try_ssl_null!(unsafe { ffi::DH_get_1024_160() });
        Ok(DH(dh))
    }

    #[cfg(all(feature = "rfc5114", not(ossl101)))]
    pub fn get_2048_224() -> Result<DH, ErrorStack> {
        let dh = try_ssl_null!(unsafe { ffi::DH_get_2048_224() });
        Ok(DH(dh))
    }

    #[cfg(all(feature = "rfc5114", not(ossl101)))]
    pub fn get_2048_256() -> Result<DH, ErrorStack> {
        let dh = try_ssl_null!(unsafe { ffi::DH_get_2048_256() });
        Ok(DH(dh))
    }

    pub unsafe fn as_ptr(&self) -> *mut ffi::DH {
        let DH(n) = *self;
        n
    }
}

impl Drop for DH {
    fn drop(&mut self) {
        unsafe {
            ffi::DH_free(self.as_ptr())
        }
    }
}

#[cfg(ossl110)]
mod compat {
    pub use ffi::DH_set0_pqg;
}

#[cfg(ossl10x)]
#[allow(bad_style)]
mod compat {
    use ffi;
    use libc::c_int;

    pub unsafe fn DH_set0_pqg(dh: *mut ffi::DH,
                              p: *mut ffi::BIGNUM,
                              q: *mut ffi::BIGNUM,
                              g: *mut ffi::BIGNUM) -> c_int {
        (*dh).p = p;
        (*dh).q = q;
        (*dh).g = g;
        1
    }
}

#[cfg(test)]
mod tests {
    use super::DH;
    use bn::BigNum;
    use ssl::SslContext;
    use ssl::SslMethod::Tls;

    #[test]
    #[cfg(all(feature = "rfc5114", not(ossl101)))]
    fn test_dh_rfc5114() {
        let mut ctx = SslContext::new(Tls).unwrap();
        let dh1 = DH::get_1024_160().unwrap();
        ctx.set_tmp_dh(&dh1).unwrap();
        let dh2 = DH::get_2048_224().unwrap();
        ctx.set_tmp_dh(&dh2).unwrap();
        let dh3 = DH::get_2048_256().unwrap();
        ctx.set_tmp_dh(&dh3).unwrap();
    }

    #[test]
    fn test_dh() {
        let mut ctx = SslContext::new(Tls).unwrap();
        let p = BigNum::from_hex_str("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435\
                                      E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF429\
                                      6D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C02\
                                      2E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF1230\
                                      7F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9\
                                      A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251C\
                                      CACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE\
                                      621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D227\
                                      6E11715F693877FAD7EF09CADB094AE91E1A1597")
                    .unwrap();
        let g = BigNum::from_hex_str("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0\
                                      BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773\
                                      BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2D\
                                      DF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428E\
                                      BC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BF\
                                      FE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7\
                                      D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92\
                                      B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148\
                                      D47954515E2327CFEF98C582664B4C0F6CC41659")
                    .unwrap();
        let q = BigNum::from_hex_str("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F\
                                      5FBD3")
                    .unwrap();
        let dh = DH::from_params(p, g, q).unwrap();
        ctx.set_tmp_dh(&dh).unwrap();
    }

    #[test]
    fn test_dh_from_pem() {
        let mut ctx = SslContext::new(Tls).unwrap();
        let params = include_bytes!("../../test/dhparams.pem");
        let dh = DH::from_pem(params).ok().expect("Failed to load PEM");
        ctx.set_tmp_dh(&dh).unwrap();
    }
}
