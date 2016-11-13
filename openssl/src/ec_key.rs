use ffi;
use std::ptr;

use {cvt, cvt_p, init};
use bn::{BigNumRef, BigNumContextRef};
use error::ErrorStack;
use nid::Nid;
use types::OpenSslTypeRef;

type_!(EcGroup, EcGroupRef, ffi::EC_GROUP, ffi::EC_GROUP_free);

impl EcGroup {
    /// Returns the group of a standard named curve.
    pub fn from_curve_name(nid: Nid) -> Result<EcGroup, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_GROUP_new_by_curve_name(nid.as_raw())).map(EcGroup)
        }
    }

    /// Constructs a curve over a prime field from its components.
    pub fn from_components_gfp(p: &BigNumRef,
                               a: &BigNumRef,
                               b: &BigNumRef,
                               ctx: &mut BigNumContextRef)
                               -> Result<EcGroup, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_GROUP_new_curve_GFp(p.as_ptr(), a.as_ptr(), b.as_ptr(), ctx.as_ptr()))
                .map(EcGroup)
        }
    }

    /// Constructs a curve over a binary field from its components.
    pub fn from_components_gf2m(p: &BigNumRef,
                                a: &BigNumRef,
                                b: &BigNumRef,
                                ctx: &mut BigNumContextRef)
                                -> Result<EcGroup, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_GROUP_new_curve_GF2m(p.as_ptr(), a.as_ptr(), b.as_ptr(), ctx.as_ptr()))
                .map(EcGroup)
        }
    }

    /// Places the components of a curve over a prime field in the provided `BigNum`s.
    pub fn components_gfp(&self,
                          p: &mut BigNumRef,
                          a: &mut BigNumRef,
                          b: &mut BigNumRef,
                          ctx: &mut BigNumContextRef)
                          -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_curve_GFp(self.as_ptr(),
                                            p.as_ptr(),
                                            a.as_ptr(),
                                            b.as_ptr(),
                                            ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Places the components of a curve over a binary field in the provided `BigNum`s.
    pub fn components_gf2m(&self,
                           p: &mut BigNumRef,
                           a: &mut BigNumRef,
                           b: &mut BigNumRef,
                           ctx: &mut BigNumContextRef)
                           -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_curve_GF2m(self.as_ptr(),
                                             p.as_ptr(),
                                             a.as_ptr(),
                                             b.as_ptr(),
                                             ctx.as_ptr()))
                .map(|_| ())
        }
    }
}

type_!(EcPoint, EcPointRef, ffi::EC_POINT, ffi::EC_POINT_free);

type_!(EcKey, EcKeyRef, ffi::EC_KEY, ffi::EC_KEY_free);

impl EcKeyRef {
    private_key_to_pem!(ffi::PEM_write_bio_ECPrivateKey);
    private_key_to_der!(ffi::i2d_ECPrivateKey);

    pub fn group(&self) -> &EcGroupRef {
        unsafe {
            let ptr = ffi::EC_KEY_get0_group(self.as_ptr());
            assert!(!ptr.is_null());
            EcGroupRef::from_ptr(ptr as *mut _)
        }
    }

    pub fn public_key(&self) -> Option<&EcPointRef> {
        unsafe {
            let ptr = ffi::EC_KEY_get0_public_key(self.as_ptr());
            assert!(!ptr.is_null());
            EcPointRef::from_ptr(ptr as *mut _)
        }
    }

    pub fn private_key(&self) -> Option<&BigNumRef> {
        unsafe {
            let ptr = ffi::EC_KEY_get0_private_key(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(ptr as *mut _))
            }
        }
    }
}

impl EcKey {
    pub fn from_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(EcKey)
        }
    }

    #[deprecated(since = "0.9.2", note = "use from_curve_name")]
    pub fn new_by_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        EcKey::from_curve_name(nid)
    }

    private_key_from_pem!(EcKey, ffi::PEM_read_bio_ECPrivateKey);
    private_key_from_der!(EcKey, ffi::d2i_ECPrivateKey);
}

#[cfg(test)]
mod test {
    use bn::{BigNum, BigNumContext};
    use nid;
    use super::*;

    #[test]
    fn key_new_by_curve_name() {
        EcKey::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
    }

    #[test]
    fn round_trip_prime256v1() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let mut p = BigNum::new().unwrap();
        let mut a = BigNum::new().unwrap();
        let mut b = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        group.components_gfp(&mut p, &mut a, &mut b, &mut ctx).unwrap();
        EcGroup::from_components_gfp(&p, &a, &b, &mut ctx).unwrap();
    }
}
