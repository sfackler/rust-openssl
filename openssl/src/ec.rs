use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ptr;
use std::mem;
use libc::c_int;

use {cvt, cvt_n, cvt_p, init};
use bn::{BigNumRef, BigNumContextRef};
use error::ErrorStack;
use nid::Nid;

pub const POINT_CONVERSION_COMPRESSED: PointConversionForm =
    PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_COMPRESSED);

pub const POINT_CONVERSION_UNCOMPRESSED: PointConversionForm =
    PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED);

pub const POINT_CONVERSION_HYBRID: PointConversionForm =
    PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_HYBRID);

// OPENSSL_EC_EXPLICIT_CURVE, but that was only added in 1.1.
// Man page documents that 0 can be used in older versions.
pub const EXPLICIT_CURVE: Asn1Flag = Asn1Flag(0);
pub const NAMED_CURVE: Asn1Flag = Asn1Flag(ffi::OPENSSL_EC_NAMED_CURVE);

#[derive(Copy, Clone)]
pub struct PointConversionForm(ffi::point_conversion_form_t);

#[derive(Copy, Clone)]
pub struct Asn1Flag(c_int);

foreign_type! {
    type CType = ffi::EC_GROUP;
    fn drop = ffi::EC_GROUP_free;

    pub struct EcGroup;
    pub struct EcGroupRef;
}

impl EcGroup {
    /// Returns the group of a standard named curve.
    pub fn from_curve_name(nid: Nid) -> Result<EcGroup, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_GROUP_new_by_curve_name(nid.as_raw())).map(EcGroup)
        }
    }
}

impl EcGroupRef {
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
    #[cfg(not(osslconf = "OPENSSL_NO_EC2M"))]
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

    /// Returns the degree of the curve.
    pub fn degree(&self) -> u32 {
        unsafe { ffi::EC_GROUP_get_degree(self.as_ptr()) as u32 }
    }

    /// Places the order of the curve in the provided `BigNum`.
    pub fn order(&self,
                 order: &mut BigNumRef,
                 ctx: &mut BigNumContextRef)
                 -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_order(self.as_ptr(), order.as_ptr(), ctx.as_ptr())).map(|_| ())
        }
    }

    /// Sets the flag determining if the group corresponds to a named curve or must be explicitly
    /// parameterized.
    ///
    /// This defaults to `EXPLICIT_CURVE` in OpenSSL 1.0.1 and 1.0.2, but `NAMED_CURVE` in OpenSSL
    /// 1.1.0.
    pub fn set_asn1_flag(&mut self, flag: Asn1Flag) {
        unsafe {
            ffi::EC_GROUP_set_asn1_flag(self.as_ptr(), flag.0);
        }
    }
}

foreign_type! {
    type CType = ffi::EC_POINT;
    fn drop = ffi::EC_POINT_free;

    pub struct EcPoint;
    pub struct EcPointRef;
}

impl EcPointRef {
    /// Computes `a + b`, storing the result in `self`.
    pub fn add(&mut self,
               group: &EcGroupRef,
               a: &EcPointRef,
               b: &EcPointRef,
               ctx: &mut BigNumContextRef)
               -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_add(group.as_ptr(),
                                  self.as_ptr(),
                                  a.as_ptr(),
                                  b.as_ptr(),
                                  ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Computes `q * m`, storing the result in `self`.
    pub fn mul(&mut self,
               group: &EcGroupRef,
               q: &EcPointRef,
               m: &BigNumRef,
               ctx: &BigNumContextRef)
               -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(group.as_ptr(),
                                  self.as_ptr(),
                                  ptr::null(),
                                  q.as_ptr(),
                                  m.as_ptr(),
                                  ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Computes `generator * n`, storing the result ing `self`.
    pub fn mul_generator(&mut self,
                         group: &EcGroupRef,
                         n: &BigNumRef,
                         ctx: &BigNumContextRef)
                         -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(group.as_ptr(),
                                  self.as_ptr(),
                                  n.as_ptr(),
                                  ptr::null(),
                                  ptr::null(),
                                  ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Computes `generator * n + q * m`, storing the result in `self`.
    pub fn mul_full(&mut self,
                    group: &EcGroupRef,
                    n: &BigNumRef,
                    q: &EcPointRef,
                    m: &BigNumRef,
                    ctx: &mut BigNumContextRef)
                    -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(group.as_ptr(),
                                  self.as_ptr(),
                                  n.as_ptr(),
                                  q.as_ptr(),
                                  m.as_ptr(),
                                  ctx.as_ptr()))
                .map(|_| ())
        }
    }

    /// Inverts `self`.
    pub fn invert(&mut self, group: &EcGroupRef, ctx: &BigNumContextRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_invert(group.as_ptr(), self.as_ptr(), ctx.as_ptr())).map(|_| ())
        }
    }

    /// Serializes the point to a binary representation.
    pub fn to_bytes(&self,
                    group: &EcGroupRef,
                    form: PointConversionForm,
                    ctx: &mut BigNumContextRef)
                    -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let len = ffi::EC_POINT_point2oct(group.as_ptr(),
                                              self.as_ptr(),
                                              form.0,
                                              ptr::null_mut(),
                                              0,
                                              ctx.as_ptr());
            if len == 0 {
                return Err(ErrorStack::get());
            }
            let mut buf = vec![0; len];
            let len = ffi::EC_POINT_point2oct(group.as_ptr(),
                                              self.as_ptr(),
                                              form.0,
                                              buf.as_mut_ptr(),
                                              len,
                                              ctx.as_ptr());
            if len == 0 {
                Err(ErrorStack::get())
            } else {
                Ok(buf)
            }
        }
    }

    /// Determines if this point is equal to another.
    pub fn eq(&self,
              group: &EcGroupRef,
              other: &EcPointRef,
              ctx: &mut BigNumContextRef)
              -> Result<bool, ErrorStack> {
        unsafe {
            let res = try!(cvt_n(ffi::EC_POINT_cmp(group.as_ptr(),
                                                   self.as_ptr(),
                                                   other.as_ptr(),
                                                   ctx.as_ptr())));
            Ok(res == 0)
        }
    }
}

impl EcPoint {
    /// Creates a new point on the specified curve.
    pub fn new(group: &EcGroupRef) -> Result<EcPoint, ErrorStack> {
        unsafe { cvt_p(ffi::EC_POINT_new(group.as_ptr())).map(EcPoint) }
    }

    pub fn from_bytes(group: &EcGroupRef,
                      buf: &[u8],
                      ctx: &mut BigNumContextRef)
                      -> Result<EcPoint, ErrorStack> {
        let point = try!(EcPoint::new(group));
        unsafe {
            try!(cvt(ffi::EC_POINT_oct2point(group.as_ptr(),
                                             point.as_ptr(),
                                             buf.as_ptr(),
                                             buf.len(),
                                             ctx.as_ptr())));
        }
        Ok(point)
    }
}

foreign_type! {
    type CType = ffi::EC_KEY;
    fn drop = ffi::EC_KEY_free;

    pub struct EcKey;
    pub struct EcKeyRef;
}

impl EcKeyRef {
    private_key_to_pem!(ffi::PEM_write_bio_ECPrivateKey);
    private_key_to_der!(ffi::i2d_ECPrivateKey);

    pub fn group(&self) -> Option<&EcGroupRef> {
        unsafe {
            let ptr = ffi::EC_KEY_get0_group(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(EcGroupRef::from_ptr(ptr as *mut _))
            }
        }
    }

    pub fn public_key(&self) -> Option<&EcPointRef> {
        unsafe {
            let ptr = ffi::EC_KEY_get0_public_key(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(EcPointRef::from_ptr(ptr as *mut _))
            }
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

    /// Checks the key for validity.
    pub fn check_key(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::EC_KEY_check_key(self.as_ptr())).map(|_| ()) }
    }

    pub fn to_owned(&self) -> Result<EcKey, ErrorStack> {
        unsafe { cvt_p(ffi::EC_KEY_dup(self.as_ptr())).map(EcKey) }
    }
}

impl EcKey {
    /// Constructs an `EcKey` corresponding to a known curve.
    ///
    /// It will not have an associated public or private key. This kind of key is primarily useful
    /// to be provided to the `set_tmp_ecdh` methods on `Ssl` and `SslContextBuilder`.
    pub fn from_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(EcKey)
        }
    }

    /// Constructs an `EcKey` from the specified group with the associated `EcPoint`, public_key.
    ///
    /// This will only have the associated public_key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use openssl::bn::BigNumContext;
    /// use openssl::ec::*;
    /// use openssl::nid;
    /// use openssl::pkey::PKey;
    ///
    /// // get bytes from somewhere, i.e. this will not produce a valid key
    /// let public_key: Vec<u8> = vec![];
    ///
    /// // create an EcKey from the binary form of a EcPoint
    /// let group = EcGroup::from_curve_name(nid::SECP256K1).unwrap();
    /// let mut ctx = BigNumContext::new().unwrap();
    /// let point = EcPoint::from_bytes(&group, &public_key, &mut ctx).unwrap();
    /// let key = EcKey::from_public_key(&group, &point);
    /// ```
    pub fn from_public_key(group: &EcGroupRef, public_key: &EcPointRef) -> Result<EcKey, ErrorStack> {
        let mut builder = try!(EcKeyBuilder::new());
        try!(builder.set_group(group));
        try!(builder.set_public_key(public_key));
        Ok(builder.build())
    }

    /// Generates a new public/private key pair on the specified curve.
    pub fn generate(group: &EcGroupRef) -> Result<EcKey, ErrorStack> {
        let mut builder = try!(EcKeyBuilder::new());
        try!(builder.set_group(group));
        try!(builder.generate_key());
        Ok(builder.build())
    }

    #[deprecated(since = "0.9.2", note = "use from_curve_name")]
    pub fn new_by_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        EcKey::from_curve_name(nid)
    }

    private_key_from_pem!(EcKey, ffi::PEM_read_bio_ECPrivateKey);
    private_key_from_der!(EcKey, ffi::d2i_ECPrivateKey);
}


foreign_type! {
    type CType = ffi::EC_KEY;
    fn drop = ffi::EC_KEY_free;

    pub struct EcKeyBuilder;
    pub struct EcKeyBuilderRef;
}

impl EcKeyBuilder {
    pub fn new() -> Result<EcKeyBuilder, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new()).map(EcKeyBuilder)
        }
    }

    pub fn build(self) -> EcKey {
        unsafe {
            let key = EcKey::from_ptr(self.as_ptr());
            mem::forget(self);
            key
        }
    }
}

impl EcKeyBuilderRef {
    pub fn set_group(&mut self, group: &EcGroupRef) -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe {
            cvt(ffi::EC_KEY_set_group(self.as_ptr(), group.as_ptr())).map(|_| self)
        }
    }

    pub fn set_public_key(&mut self,
                          public_key: &EcPointRef)
                          -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe {
            cvt(ffi::EC_KEY_set_public_key(self.as_ptr(), public_key.as_ptr())).map(|_| self)
        }
    }

    pub fn generate_key(&mut self) -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe {
            cvt(ffi::EC_KEY_generate_key(self.as_ptr())).map(|_| self)
        }
    }
}

#[cfg(test)]
mod test {
    use bn::BigNumContext;
    use nid;
    use super::*;

    #[test]
    fn key_new_by_curve_name() {
        EcKey::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
    }

    #[test]
    fn generate() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        key.public_key().unwrap();
        key.private_key().unwrap();
    }

    #[test]
    fn dup() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        key.to_owned().unwrap();
    }

    #[test]
    fn point_new() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        EcPoint::new(&group).unwrap();
    }

    #[test]
    fn point_bytes() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let point = key.public_key().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let bytes = point.to_bytes(&group, POINT_CONVERSION_COMPRESSED, &mut ctx).unwrap();
        let point2 = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        assert!(point.eq(&group, &point2, &mut ctx).unwrap());
    }

    #[test]
    fn mul_generator() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut public_key = EcPoint::new(&group).unwrap();
        public_key.mul_generator(&group, key.private_key().unwrap(), &mut ctx).unwrap();
        assert!(public_key.eq(&group, key.public_key().unwrap(), &mut ctx).unwrap());
    }

    #[test]
    fn key_from_public_key() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let bytes = key.public_key().unwrap().to_bytes(&group, POINT_CONVERSION_COMPRESSED, &mut ctx).unwrap();

        drop(key);
        let public_key = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        let ec_key = EcKey::from_public_key(&group, &public_key).unwrap();
        assert!(ec_key.check_key().is_ok());
        assert!(ec_key.public_key().is_some());
        assert!(ec_key.private_key().is_none());
    }
}
