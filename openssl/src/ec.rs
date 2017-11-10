//! Elliptic Curve
//!
//! Cryptology relies on the difficulty of solving mathematical problems, such as the factor
//! of large integers composed of two large prime numbers and the discrete logarithm of a
//! random eliptic curve.  This module provides low-level features of the latter.
//! Elliptic Curve protocols can provide the same security with smaller keys.
//!
//! There are 2 forms of elliptic curves, `Fp` and `F2^m`.  These curves use irreducible
//! trinomial or pentanomial .  Being a generic interface to a wide range of algorithms,
//! the cuves are generally referenced by [`EcGroup`].  There are many built in groups
//! found in [`Nid`].
//!
//! OpenSSL Wiki explains the fields and curves in detail at [Eliptic Curve Cryptography].
//!
//! [`EcGroup`]: struct.EcGroup.html
//! [`Nid`]: ../nid/struct.Nid.html
//! [Eliptic Curve Cryptography]: https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography
//!
//! # Examples
//!
//! ```
//! use openssl::ec::{EcGroup, EcPoint};
//! use openssl::nid;
//! use openssl::error::ErrorStack;
//! fn get_ec_point() -> Result< EcPoint, ErrorStack > {
//!    let group = EcGroup::from_curve_name(nid::SECP224R1)?;
//!    let point = EcPoint::new(&group)?;
//!    Ok(point)
//! }
//! # fn main() {
//! #    let _ = get_ec_point();
//! # }
//! ```
use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ptr;
use std::mem;
use libc::c_int;

use {cvt, cvt_n, cvt_p, init};
use bn::{BigNumRef, BigNumContextRef};
use error::ErrorStack;
use nid::Nid;

/// Compressed conversion from point value (Default)
pub const POINT_CONVERSION_COMPRESSED: PointConversionForm =
    PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_COMPRESSED);

/// Uncompressed conversion from point value (Binary curve default)
pub const POINT_CONVERSION_UNCOMPRESSED: PointConversionForm =
    PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED);

/// Performs both compressed and uncompressed conversions
pub const POINT_CONVERSION_HYBRID: PointConversionForm =
    PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_HYBRID);

/// Curve defined using polynomial parameters
///
/// Most applications use a named EC_GROUP curve, however, support
/// is included to explicitly define the curve used to calculate keys
/// This information would need to be known by both endpoint to make communication
/// effective.
///
/// OPENSSL_EC_EXPLICIT_CURVE, but that was only added in 1.1.
/// Man page documents that 0 can be used in older versions.
///
/// OpenSSL documentation at [`EC_GROUP`]
///
/// [`EC_GROUP`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_seed_len.html
pub const EXPLICIT_CURVE: Asn1Flag = Asn1Flag(0);

/// Standard Curves
///
/// Curves that make up the typical encryption use cases.  The collection of curves
/// are well known but extensible.
///
/// OpenSSL documentation at [`EC_GROUP`]
///
/// [`EC_GROUP`]: https://www.openssl.org/docs/manmaster/man3/EC_GROUP_order_bits.html
pub const NAMED_CURVE: Asn1Flag = Asn1Flag(ffi::OPENSSL_EC_NAMED_CURVE);

/// Compressed or Uncompressed conversion
///
/// Conversion from the binary value of the point on the curve is performed in one of
/// compressed, uncompressed, or hybrid conversions.  The default is compressed, except
/// for binary curves.
///
/// Further documentation is available in the [X9.62] standard.
///
/// [X9.62]: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf
#[derive(Copy, Clone)]
pub struct PointConversionForm(ffi::point_conversion_form_t);

/// Named Curve or Explicit
///
/// This type acts as a boolean as to whether the EC_Group is named or
/// explicit.
#[derive(Copy, Clone)]
pub struct Asn1Flag(c_int);

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_GROUP;
    fn drop = ffi::EC_GROUP_free;

    /// Describes the curve
    ///
    /// A curve can be of the named curve type.  These curves can be discovered
    /// using openssl binary `openssl ecparam -list_curves`.  Other operations
    /// are available in the [wiki].  These named curves are available in the
    /// [`Nid`] module.
    ///
    /// Curves can also be generated using prime field parameters or a binary field.
    ///
    /// Prime fields use the formula `y^2 mod p = x^3 + ax + b mod p`.  Binary
    /// fields use the formula `y^2 + xy = x^3 + ax^2 + b`.  Named curves have
    /// assured security.  To prevent accidental vulnerabilities, they should
    /// be prefered.
    ///
    /// [wiki]: https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations
    /// [`Nid`]: ../nid/index.html
    pub struct EcGroup;
    /// Reference to [`EcGroup`]
    ///
    /// [`EcGroup`]: struct.EcGroup.html
    pub struct EcGroupRef;
}

impl EcGroup {
    /// Returns the group of a standard named curve.
    ///
    /// OpenSSL documentation at [`EC_GROUP_new`].
    ///
    /// [`EC_GROUP_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_new.html
    pub fn from_curve_name(nid: Nid) -> Result<EcGroup, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_GROUP_new_by_curve_name(nid.as_raw())).map(EcGroup)
        }
    }
}

impl EcGroupRef {
    /// Places the components of a curve over a prime field in the provided `BigNum`s.
    /// The components make up the formula `y^2 mod p = x^3 + ax + b mod p`.
    ///
    /// OpenSSL documentation available at [`EC_GROUP_get_curve_GFp`]
    ///
    /// [`EC_GROUP_get_curve_GFp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_curve_GFp.html
    pub fn components_gfp(
        &self,
        p: &mut BigNumRef,
        a: &mut BigNumRef,
        b: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_curve_GFp(
                self.as_ptr(),
                p.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Places the components of a curve over a binary field in the provided `BigNum`s.
    /// The components make up the formula `y^2 + xy = x^3 + ax^2 + b`.
    ///
    /// In this form `p` relates to the irreducible polynomial.  Each bit represents
    /// a term in the polynomial.  It will be set to 3 `1`s or 5 `1`s depending on
    /// using a trinomial or pentanomial.
    ///
    /// OpenSSL documentation at [`EC_GROUP_get_curve_GF2m`].
    ///
    /// [`EC_GROUP_get_curve_GF2m`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_curve_GF2m.html
    #[cfg(not(osslconf = "OPENSSL_NO_EC2M"))]
    pub fn components_gf2m(
        &self,
        p: &mut BigNumRef,
        a: &mut BigNumRef,
        b: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_curve_GF2m(
                self.as_ptr(),
                p.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Returns the degree of the curve.
    ///
    /// OpenSSL documentation at [`EC_GROUP_get_degree`]
    ///
    /// [`EC_GROUP_get_degree`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_degree.html
    pub fn degree(&self) -> u32 {
        unsafe { ffi::EC_GROUP_get_degree(self.as_ptr()) as u32 }
    }

    /// Places the order of the curve in the provided `BigNum`.
    ///
    /// OpenSSL documentation at [`EC_GROUP_get_order`]
    ///
    /// [`EC_GROUP_get_order`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_order.html
    pub fn order(
        &self,
        order: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_order(
                self.as_ptr(),
                order.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
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

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_POINT;
    fn drop = ffi::EC_POINT_free;

    /// Represents a point on the curve
    ///
    /// OpenSSL documentation at [`EC_POINT_new`]
    ///
    /// [`EC_POINT_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_new.html
    pub struct EcPoint;
    /// Reference to [`EcPoint`]
    ///
    /// [`EcPoint`]: struct.EcPoint.html
    pub struct EcPointRef;
}

impl EcPointRef {
    /// Computes `a + b`, storing the result in `self`.
    ///
    /// OpenSSL documentation at [`EC_POINT_add`]
    ///
    /// [`EC_POINT_add`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_add.html
    pub fn add(
        &mut self,
        group: &EcGroupRef,
        a: &EcPointRef,
        b: &EcPointRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_add(
                group.as_ptr(),
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Computes `q * m`, storing the result in `self`.
    ///
    /// OpenSSL documentation at [`EC_POINT_mul`]
    ///
    /// [`EC_POINT_mul`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_mul.html
    pub fn mul(
        &mut self,
        group: &EcGroupRef,
        q: &EcPointRef,
        m: &BigNumRef,
        ctx: &BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                ptr::null(),
                q.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Computes `generator * n`, storing the result ing `self`.
    pub fn mul_generator(
        &mut self,
        group: &EcGroupRef,
        n: &BigNumRef,
        ctx: &BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                n.as_ptr(),
                ptr::null(),
                ptr::null(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Computes `generator * n + q * m`, storing the result in `self`.
    pub fn mul_full(
        &mut self,
        group: &EcGroupRef,
        n: &BigNumRef,
        q: &EcPointRef,
        m: &BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                n.as_ptr(),
                q.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Inverts `self`.
    ///
    /// OpenSSL documentation at [`EC_POINT_invert`]
    ///
    /// [`EC_POINT_invert`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_invert.html
    pub fn invert(&mut self, group: &EcGroupRef, ctx: &BigNumContextRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_invert(
                group.as_ptr(),
                self.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Serializes the point to a binary representation.
    ///
    /// OpenSSL documentation at [`EC_POINT_point2oct`]
    ///
    /// [`EC_POINT_point2oct`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_point2oct.html
    pub fn to_bytes(
        &self,
        group: &EcGroupRef,
        form: PointConversionForm,
        ctx: &mut BigNumContextRef,
    ) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let len = ffi::EC_POINT_point2oct(
                group.as_ptr(),
                self.as_ptr(),
                form.0,
                ptr::null_mut(),
                0,
                ctx.as_ptr(),
            );
            if len == 0 {
                return Err(ErrorStack::get());
            }
            let mut buf = vec![0; len];
            let len = ffi::EC_POINT_point2oct(
                group.as_ptr(),
                self.as_ptr(),
                form.0,
                buf.as_mut_ptr(),
                len,
                ctx.as_ptr(),
            );
            if len == 0 {
                Err(ErrorStack::get())
            } else {
                Ok(buf)
            }
        }
    }

    /// Determines if this point is equal to another.
    ///
    /// OpenSSL doucmentation at [`EC_POINT_cmp`]
    ///
    /// [`EC_POINT_cmp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_cmp.html
    pub fn eq(
        &self,
        group: &EcGroupRef,
        other: &EcPointRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<bool, ErrorStack> {
        unsafe {
            let res = cvt_n(ffi::EC_POINT_cmp(
                group.as_ptr(),
                self.as_ptr(),
                other.as_ptr(),
                ctx.as_ptr(),
            ))?;
            Ok(res == 0)
        }
    }

    /// Place affine coordinates of a curve over a prime field in the provided
    /// `x` and `y` `BigNum`s
    ///
    /// OpenSSL documentation at [`EC_POINT_get_affine_coordinates_GFp`]
    ///
    /// [`EC_POINT_get_affine_coordinates_GFp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_get_affine_coordinates_GFp.html
    pub fn affine_coordinates_gfp(
        &self,
        group: &EcGroupRef,
        x: &mut BigNumRef,
        y: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_get_affine_coordinates_GFp(
                group.as_ptr(),
                self.as_ptr(),
                x.as_ptr(),
                y.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }

    /// Place affine coordinates of a curve over a binary field in the provided
    /// `x` and `y` `BigNum`s
    ///
    /// OpenSSL documentation at [`EC_POINT_get_affine_coordinates_GF2m`]
    ///
    /// [`EC_POINT_get_affine_coordinates_GF2m`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_get_affine_coordinates_GF2m.html
    #[cfg(not(osslconf = "OPENSSL_NO_EC2M"))]
    pub fn affine_coordinates_gf2m(
        &self,
        group: &EcGroupRef,
        x: &mut BigNumRef,
        y: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_get_affine_coordinates_GF2m(
                group.as_ptr(),
                self.as_ptr(),
                x.as_ptr(),
                y.as_ptr(),
                ctx.as_ptr(),
            )).map(|_| ())
        }
    }
}

impl EcPoint {
    /// Creates a new point on the specified curve.
    ///
    /// OpenSSL documentation at [`EC_POINT_new`]
    ///
    /// [`EC_POINT_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_new.html
    pub fn new(group: &EcGroupRef) -> Result<EcPoint, ErrorStack> {
        unsafe { cvt_p(ffi::EC_POINT_new(group.as_ptr())).map(EcPoint) }
    }

    /// Creates point from a binary representation
    ///
    /// OpenSSL documentation at [`EC_POINT_oct2point`]
    ///
    /// [`EC_POINT_oct2point`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_oct2point.html
    pub fn from_bytes(
        group: &EcGroupRef,
        buf: &[u8],
        ctx: &mut BigNumContextRef,
    ) -> Result<EcPoint, ErrorStack> {
        let point = EcPoint::new(group)?;
        unsafe {
            cvt(ffi::EC_POINT_oct2point(
                group.as_ptr(),
                point.as_ptr(),
                buf.as_ptr(),
                buf.len(),
                ctx.as_ptr(),
            ))?;
        }
        Ok(point)
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_KEY;
    fn drop = ffi::EC_KEY_free;

    /// Public and optional Private key on the given curve
    ///
    /// OpenSSL documentation at [`EC_KEY_new`]
    ///
    /// [`EC_KEY_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_new.html
    pub struct EcKey;
    /// Reference to [`EcKey`]
    ///
    /// [`EcKey`]: struct.EcKey.html
    pub struct EcKeyRef;
}

impl EcKeyRef {
    private_key_to_pem!(ffi::PEM_write_bio_ECPrivateKey);
    private_key_to_der!(ffi::i2d_ECPrivateKey);

    /// Return [`EcGroup`] of the `EcKey`
    ///
    /// OpenSSL documentation at [`EC_KEY_get0_group`]
    ///
    /// [`EC_KEY_get0_group`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_get0_group.html
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

    /// Return [`EcPoint`] associated with the public key
    ///
    /// OpenSSL documentation at [`EC_KEY_get0_pubic_key`]
    ///
    /// [`EC_KEY_get0_pubic_key`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_get0_public_key.html
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

    /// Return [`EcPoint`] associated with the private key
    ///
    /// OpenSSL documentation at [`EC_KEY_get0_private_key`]
    ///
    /// [`EC_KEY_get0_private_key`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_get0_private_key.html
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
    ///
    /// OpenSSL documenation at [`EC_KEY_check_key`]
    ///
    /// [`EC_KEY_check_key`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_check_key.html
    pub fn check_key(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::EC_KEY_check_key(self.as_ptr())).map(|_| ()) }
    }

    /// Create a copy of the `EcKey` to allow modification
    pub fn to_owned(&self) -> Result<EcKey, ErrorStack> {
        unsafe { cvt_p(ffi::EC_KEY_dup(self.as_ptr())).map(EcKey) }
    }
}

impl EcKey {
    /// Constructs an `EcKey` corresponding to a known curve.
    ///
    /// It will not have an associated public or private key. This kind of key is primarily useful
    /// to be provided to the `set_tmp_ecdh` methods on `Ssl` and `SslContextBuilder`.
    ///
    /// OpenSSL documenation at [`EC_KEY_new_by_curve_name`]
    ///
    /// [`EC_KEY_new_by_curve_name`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_new_by_curve_name.html
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
    pub fn from_public_key(
        group: &EcGroupRef,
        public_key: &EcPointRef,
    ) -> Result<EcKey, ErrorStack> {
        let mut builder = EcKeyBuilder::new()?;
        builder.set_group(group)?;
        builder.set_public_key(public_key)?;
        Ok(builder.build())
    }

    /// Generates a new public/private key pair on the specified curve.
    pub fn generate(group: &EcGroupRef) -> Result<EcKey, ErrorStack> {
        let mut builder = EcKeyBuilder::new()?;
        builder.set_group(group)?;
        builder.generate_key()?;
        Ok(builder.build())
    }

    #[deprecated(since = "0.9.2", note = "use from_curve_name")]
    pub fn new_by_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        EcKey::from_curve_name(nid)
    }

    private_key_from_pem!(EcKey, ffi::PEM_read_bio_ECPrivateKey);
    private_key_from_der!(EcKey, ffi::d2i_ECPrivateKey);
}


foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_KEY;
    fn drop = ffi::EC_KEY_free;

    /// Builder pattern for key generation
    ///
    /// Returns a `EcKeyBuilder` to be consumed by `build`
    pub struct EcKeyBuilder;
    /// Reference to [`EcKeyBuilder`]
    ///
    /// [`EcKeyBuilder`]: struct.EcKeyBuilder.html
    pub struct EcKeyBuilderRef;
}

impl EcKeyBuilder {
    /// Creates an empty `EcKeyBuilder` to be chained with additonal methods
    pub fn new() -> Result<EcKeyBuilder, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new()).map(EcKeyBuilder)
        }
    }

    /// Consume the `EcKeyBuilder` and return [`EcKey`]
    ///
    /// [`EcKey`]: struct.EcKey.html
    pub fn build(self) -> EcKey {
        unsafe {
            let key = EcKey::from_ptr(self.as_ptr());
            mem::forget(self);
            key
        }
    }
}

impl EcKeyBuilderRef {
    /// Set the [`EcGroup`] explicitly
    ///
    /// [`EcGroup`]: struct.EcGroup.html
    pub fn set_group(&mut self, group: &EcGroupRef) -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe { cvt(ffi::EC_KEY_set_group(self.as_ptr(), group.as_ptr())).map(|_| self) }
    }

    /// Set public key to given `EcPoint`
    pub fn set_public_key(
        &mut self,
        public_key: &EcPointRef,
    ) -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe {
            cvt(ffi::EC_KEY_set_public_key(
                self.as_ptr(),
                public_key.as_ptr(),
            )).map(|_| self)
        }
    }

    /// Generate public and private keys.
    pub fn generate_key(&mut self) -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe { cvt(ffi::EC_KEY_generate_key(self.as_ptr())).map(|_| self) }
    }

    /// Sets the public key based on affine coordinates.
    pub fn set_public_key_affine_coordinates(
        &mut self,
        x: &BigNumRef,
        y: &BigNumRef,
    ) -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe {
            cvt(ffi::EC_KEY_set_public_key_affine_coordinates(
                self.as_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            )).map(|_| self)
        }
    }

    /// Sets the private key.
    pub fn set_private_key(&mut self, key: &BigNumRef) -> Result<&mut EcKeyBuilderRef, ErrorStack> {
        unsafe { cvt(ffi::EC_KEY_set_private_key(self.as_ptr(), key.as_ptr())).map(|_| self) }
    }
}

#[cfg(test)]
mod test {
    use bn::{BigNum, BigNumContext};
    use nid;
    use data_encoding::BASE64URL_NOPAD;
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
        let bytes = point
            .to_bytes(&group, POINT_CONVERSION_COMPRESSED, &mut ctx)
            .unwrap();
        let point2 = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        assert!(point.eq(&group, &point2, &mut ctx).unwrap());
    }

    #[test]
    fn mul_generator() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut public_key = EcPoint::new(&group).unwrap();
        public_key
            .mul_generator(&group, key.private_key().unwrap(), &mut ctx)
            .unwrap();
        assert!(
            public_key
                .eq(&group, key.public_key().unwrap(), &mut ctx)
                .unwrap()
        );
    }

    #[test]
    fn key_from_public_key() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let bytes = key.public_key()
            .unwrap()
            .to_bytes(&group, POINT_CONVERSION_COMPRESSED, &mut ctx)
            .unwrap();

        drop(key);
        let public_key = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        let ec_key = EcKey::from_public_key(&group, &public_key).unwrap();
        assert!(ec_key.check_key().is_ok());
        assert!(ec_key.public_key().is_some());
        assert!(ec_key.private_key().is_none());
    }

    #[test]
    fn key_from_affine_coordinates() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let x = BASE64URL_NOPAD.decode(
            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".as_bytes(),
        ).unwrap();
        let y = BASE64URL_NOPAD.decode(
            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".as_bytes(),
        ).unwrap();

        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();

        let mut builder = EcKeyBuilder::new().unwrap();
        builder.set_group(&group).unwrap();
        builder
            .set_public_key_affine_coordinates(&xbn, &ybn)
            .unwrap();

        let ec_key = builder.build();
        assert!(ec_key.check_key().is_ok());
        assert!(ec_key.public_key().is_some());
    }

    #[test]
    fn set_private_key() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let d = BASE64URL_NOPAD.decode(
            "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE".as_bytes(),
        ).unwrap();

        let dbn = BigNum::from_slice(&d).unwrap();

        let mut builder = EcKeyBuilder::new().unwrap();
        builder.set_group(&group).unwrap();
        builder.set_private_key(&dbn).unwrap();

        let ec_key = builder.build();
        assert!(ec_key.private_key().is_some());
    }

    #[test]
    fn get_affine_coordinates() {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let x = BASE64URL_NOPAD.decode(
            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".as_bytes(),
        ).unwrap();
        let y = BASE64URL_NOPAD.decode(
            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".as_bytes(),
        ).unwrap();

        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();

        let mut builder = EcKeyBuilder::new().unwrap();
        builder.set_group(&group).unwrap();
        builder
            .set_public_key_affine_coordinates(&xbn, &ybn)
            .unwrap();

        let ec_key = builder.build();

        let mut xbn2 = BigNum::new().unwrap();
        let mut ybn2 = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let ec_key_pk = ec_key.public_key().unwrap();
        ec_key_pk
            .affine_coordinates_gfp(&group, &mut xbn2, &mut ybn2, &mut ctx)
            .unwrap();
        assert_eq!(xbn2, xbn);
        assert_eq!(ybn2, ybn);
    }
}
