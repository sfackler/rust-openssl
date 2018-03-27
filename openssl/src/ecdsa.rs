//! Low level Elliptic Curve Digital Signature Algorithm (ECDSA) functions.
use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::mem;

use bn::{BigNum, BigNumRef};
use {cvt, cvt_n, cvt_p};
use ec::EcKeyRef;
use error::ErrorStack;
use pkey::{Private, Public};

foreign_type_and_impl_send_sync! {
    type CType = ffi::ECDSA_SIG;
    fn drop = ffi::ECDSA_SIG_free;

    /// A low level interface to ECDSA
    ///
    /// OpenSSL documentation at [`ECDSA_sign`]
    ///
    /// [`ECDSA_sign`]: https://www.openssl.org/docs/man1.1.0/crypto/ECDSA_sign.html
    pub struct EcdsaSig;
    /// Reference to [`EcdsaSig`]
    ///
    /// [`EcdsaSig`]: struct.EcdsaSig.html
    pub struct EcdsaSigRef;
}

impl EcdsaSig {
    /// Computes a digital signature of the hash value `data` using the private EC key eckey.
    ///
    /// OpenSSL documentation at [`ECDSA_do_sign`]
    ///
    /// [`ECDSA_do_sign`]: https://www.openssl.org/docs/man1.1.0/crypto/ECDSA_do_sign.html
    pub fn sign(data: &[u8], eckey: &EcKeyRef<Private>) -> Result<EcdsaSig, ErrorStack> {
        unsafe {
            assert!(data.len() <= c_int::max_value() as usize);
            let sig = cvt_p(ffi::ECDSA_do_sign(
                data.as_ptr(),
                data.len() as c_int,
                eckey.as_ptr(),
            ))?;
            Ok(EcdsaSig::from_ptr(sig as *mut _))
        }
    }

    /// Returns a new `EcdsaSig` by setting the `r` and `s` values associated with a
    /// ECDSA signature.
    ///
    /// OpenSSL documentation at [`ECDSA_SIG_set0`]
    ///
    /// [`ECDSA_SIG_set0`]: https://www.openssl.org/docs/man1.1.0/crypto/ECDSA_SIG_set0.html
    pub fn from_private_components(r: BigNum, s: BigNum) -> Result<EcdsaSig, ErrorStack> {
        unsafe {
            let sig = cvt_p(ffi::ECDSA_SIG_new())?;
            cvt(compat::set_numbers(sig, r.as_ptr(), s.as_ptr()))?;
            mem::forget((r, s));
            Ok(EcdsaSig::from_ptr(sig as *mut _))
        }
    }

    /// Verifies if the signature is a valid ECDSA signature using the given public key.
    ///
    /// OpenSSL documentation at [`ECDSA_do_verify`]
    ///
    /// [`ECDSA_do_verify`]: https://www.openssl.org/docs/man1.1.0/crypto/ECDSA_do_verify.html
    pub fn verify(&self, data: &[u8], eckey: &EcKeyRef<Public>) -> Result<bool, ErrorStack> {
        unsafe {
            assert!(data.len() <= c_int::max_value() as usize);
            cvt_n(ffi::ECDSA_do_verify(
                data.as_ptr(),
                data.len() as c_int,
                self.as_ptr(),
                eckey.as_ptr(),
            )).map(|x| x == 1)
        }
    }

    /// Returns internal component: `r` of a `EcdsaSig`. (See X9.62 or FIPS 186-2)
    ///
    /// OpenSSL documentation at [`ECDSA_SIG_get0`]
    ///
    /// [`ECDSA_SIG_get0`]: https://www.openssl.org/docs/man1.1.0/crypto/ECDSA_SIG_get0.html
    pub fn r(&self) -> &BigNumRef {
        unsafe {
            let xs = compat::get_numbers(self.as_ptr());
            BigNumRef::from_ptr(xs[0] as *mut _)
        }
    }

    /// Returns internal components: `s` of a `EcdsaSig`. (See X9.62 or FIPS 186-2)
    ///
    /// OpenSSL documentation at [`ECDSA_SIG_get0`]
    ///
    /// [`ECDSA_SIG_get0`]: https://www.openssl.org/docs/man1.1.0/crypto/ECDSA_SIG_get0.html
    pub fn s(&self) -> &BigNumRef {
        unsafe {
            let xs = compat::get_numbers(self.as_ptr());
            BigNumRef::from_ptr(xs[1] as *mut _)
        }
    }
}

#[cfg(ossl110)]
mod compat {
    use std::ptr;

    use libc::c_int;
    use ffi::{self, BIGNUM, ECDSA_SIG};

    pub unsafe fn set_numbers(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> c_int {
        ffi::ECDSA_SIG_set0(sig, r, s)
    }

    pub unsafe fn get_numbers(sig: *mut ECDSA_SIG) -> [*const BIGNUM; 2] {
        let (mut r, mut s) = (ptr::null(), ptr::null());
        ffi::ECDSA_SIG_get0(sig, &mut r, &mut s);
        [r, s]
    }
}

#[cfg(ossl10x)]
mod compat {
    use libc::c_int;
    use ffi::{BIGNUM, ECDSA_SIG};

    pub unsafe fn set_numbers(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> c_int {
        (*sig).r = r;
        (*sig).s = s;
        1
    }

    pub unsafe fn get_numbers(sig: *mut ECDSA_SIG) -> [*const BIGNUM; 2] {
        [(*sig).r, (*sig).s]
    }

}

#[cfg(test)]
mod test {
    use nid::Nid;
    use ec::EcGroup;
    use ec::EcKey;
    use super::*;

    #[cfg(not(osslconf = "OPENSSL_NO_EC2M"))]
    static CURVE_IDENTIFER: Nid = Nid::X9_62_PRIME192V1;

    #[cfg(osslconf = "OPENSSL_NO_EC2M")]
    static CURVE_IDENTIFER: Nid = Nid::X9_62_C2TNB191V1;

    fn get_public_key(group: &EcGroup, x: &EcKey<Private>) -> Result<EcKey<Public>, ErrorStack> {
        let public_key_point = x.public_key();
        Ok(EcKey::from_public_key(group, public_key_point)?)
    }

    #[test]
    fn sign_and_verify() {
        let group = EcGroup::from_curve_name(CURVE_IDENTIFER).unwrap();
        let private_key = EcKey::generate(&group).unwrap();
        let public_key = get_public_key(&group, &private_key).unwrap();

        let private_key2 = EcKey::generate(&group).unwrap();
        let public_key2 = get_public_key(&group, &private_key2).unwrap();

        let data = String::from("hello");
        let res = EcdsaSig::sign(data.as_bytes(), &private_key).unwrap();

        // Signature can be verified using the correct data & correct public key
        let verification = res.verify(data.as_bytes(), &public_key).unwrap();
        assert!(verification);

        // Signature will not be verified using the incorrect data but the correct public key
        let verification2 = res.verify(String::from("hello2").as_bytes(), &public_key)
            .unwrap();
        assert!(verification2 == false);

        // Signature will not be verified using the correct data but the incorrect public key
        let verification3 = res.verify(data.as_bytes(), &public_key2).unwrap();
        assert!(verification3 == false);
    }

    #[test]
    fn check_private_components() {
        let group = EcGroup::from_curve_name(CURVE_IDENTIFER).unwrap();
        let private_key = EcKey::generate(&group).unwrap();
        let public_key = get_public_key(&group, &private_key).unwrap();
        let data = String::from("hello");
        let res = EcdsaSig::sign(data.as_bytes(), &private_key).unwrap();

        let verification = res.verify(data.as_bytes(), &public_key).unwrap();
        assert!(verification);

        let r = res.r().to_owned().unwrap();
        let s = res.s().to_owned().unwrap();

        let res2 = EcdsaSig::from_private_components(r, s).unwrap();
        let verification2 = res2.verify(data.as_bytes(), &public_key).unwrap();
        assert!(verification2);
    }
}
