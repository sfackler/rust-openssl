use libc::{c_int, size_t, c_void};
use std::ptr;

use ffi;
use ssl::error::SslError;
use bn::BigNum;

// These values are the NID values for each curve, found in obj_mac.h
// This wrapper currently only supports prime fields, not binary fields
#[derive(Copy, Clone, Debug)]
pub enum Curve {
    Secp112r1 = 704,
    Secp112r2 = 705,
    Secp128r1 = 706,
    Secp128r2 = 707,
    Secp160k1 = 708,
    Secp160r1 = 709,
    Secp160r2 = 710,
    Secp192k1 = 711,
    Secp224k1 = 712,
    Secp224r1 = 713,
    Secp256k1 = 714,
    Secp384r1 = 715,
    Secp521r1 = 716,
    Prime192v1 = 409,
    Prime192v2 = 410,
    Prime192v3 = 411,
    Prime239v1 = 412,
    Prime239v2 = 413,
    Prime239v3 = 414,
    Prime256v1 = 415,
}

pub struct EcKey(*mut ffi::EC_KEY);

impl EcKey {
    pub fn new(curve: &Curve) -> Result<Self, SslError> {
        unsafe {
            ffi::init();

            let k = try_ssl_null!(ffi::EC_KEY_new_by_curve_name(*curve as c_int));
            Ok(EcKey(k))
        }
    }

    pub fn set_private_key(&mut self, p: &BigNum) -> Result<(), SslError> {
        unsafe {
            try_ssl!(ffi::EC_KEY_set_private_key(self.raw(), p.raw()));
            Ok(())
        }
    }

    /// Generates a new public and private key pair.
    pub fn generate(curve: &Curve) -> Result<Self, SslError> {
        unsafe {
            ffi::init();

            let k = try_ssl_null!(ffi::EC_KEY_new_by_curve_name(*curve as c_int));
            try_ssl!(ffi::EC_KEY_generate_key(k));
            Ok(EcKey(k))
        }
    }

    pub fn get_public_key(&self) -> Result<EcPoint, SslError> {
        unsafe {
            let p = try_ssl_null!(ffi::EC_KEY_get0_public_key(self.raw()));
            let group = try_ssl_null!(ffi::EC_KEY_get0_group(self.raw()));
            //TODO can we not do this copying?
            let p_copy = try_ssl_null!(ffi::EC_POINT_new(group));
            try_ssl!(ffi::EC_POINT_copy(p_copy, p));
            Ok(EcPoint(p_copy))
        }
    }

    unsafe fn raw(&self) -> *mut ffi::EC_KEY {
        let EcKey(k) = *self;
        k
    }
}

impl Drop for EcKey {
    fn drop(&mut self) {
        unsafe {
            if !self.raw().is_null() {
                ffi::EC_KEY_free(self.raw());
            }
        }
    }
}

struct EcGroup(*mut ffi::EC_GROUP);

impl EcGroup {
    fn new_from_curve(curve: &Curve) -> Result<Self, SslError> {
        let g = unsafe { try_ssl_null!(ffi::EC_GROUP_new_by_curve_name(*curve as c_int)) };
        Ok(EcGroup(g))
    }

    unsafe fn raw(&self) -> *mut ffi::EC_GROUP {
        let EcGroup(g) = *self;
        g
    }
}

impl Drop for EcGroup {
    fn drop(&mut self) {
        unsafe {
            if !self.raw().is_null() {
                ffi::EC_GROUP_free(self.raw());
            }
        }
    }
}

pub struct EcPoint(*mut ffi::EC_POINT);

impl EcPoint {
    pub fn from_coordinates(curve: &Curve, x: &BigNum, y: &BigNum) -> Result<Self, SslError> {
        unsafe {
            ffi::init();

            let group = try!(EcGroup::new_from_curve(curve));
            let p = try_ssl_null!(ffi::EC_POINT_new(group.raw()));
            try!(with_ctx!(ctx, {
                // TODO get the type of the curve, then set affine coordinates appropriately.
                //      see line 145 of ecdhtest.c in the openssl source.
                Ok(try_ssl!(ffi::EC_POINT_set_affine_coordinates_GFp(group.raw(), p, x.raw(), y.raw(), ctx)))
            }));
            Ok(EcPoint(p))
        }
    }

    pub fn get_coordinates(&self, curve: &Curve) -> Result<(BigNum, BigNum), SslError> {
        unsafe {
            ffi::init();

            let group = try!(EcGroup::new_from_curve(curve));
            let x = try!(BigNum::new());
            let y = try!(BigNum::new());
            try!(with_ctx!(ctx, {
                Ok(try_ssl!(ffi::EC_POINT_get_affine_coordinates_GFp(group.raw(), self.raw(), x.raw(), y.raw(), ctx)))
            }));
            Ok((x, y))
        }
    }

    unsafe fn raw(&self) -> *mut ffi::EC_POINT {
        let EcPoint(p) = *self;
        p
    }
}

impl Drop for EcPoint {
    fn drop(&mut self) {
        unsafe {
            if !self.raw().is_null() {
                ffi::EC_POINT_free(self.raw());
            }
        }
    }
}

pub fn compute_key(key: &EcKey, pub_key: &EcPoint) -> Result<Vec<u8>, SslError> {
    unsafe {
        let group = try_ssl_null!(ffi::EC_KEY_get0_group(key.raw()));
        let num_bits_needed = ffi::EC_GROUP_get_degree(group);
        let num_bytes_needed = (num_bits_needed + 7) / 8;
        let mut buff = Vec::with_capacity(num_bytes_needed as usize);
        let secret_size = ffi::ECDH_compute_key(buff.as_mut_ptr() as *mut c_void, num_bytes_needed as size_t,
                                                pub_key.raw(), key.raw(), None);
        if secret_size <= 0 {
            Err(SslError::get())
        } else {
            buff.set_len(secret_size as usize);
            Ok(buff)
        }
    }
}

#[cfg(test)]
mod tests {
    use ec::{EcKey, EcPoint, Curve, compute_key};
    use bn::BigNum;

    #[test]
    fn test_ecdh_symmetric() {
        // A few randomly selected curves
        for curve in vec![Curve::Secp112r1, Curve::Secp160k1, Curve::Prime192v1, Curve::Prime256v1] {
            let alice_key = EcKey::generate(&curve).unwrap();
            let bob_key = EcKey::generate(&curve).unwrap();

            let alice_pub_key = alice_key.get_public_key().unwrap();
            let bob_pub_key = bob_key.get_public_key().unwrap();

            let alice_secret = compute_key(&alice_key, &bob_pub_key).unwrap();
            let bob_secret = compute_key(&bob_key, &alice_pub_key).unwrap();
            assert_eq!(alice_secret, bob_secret);
        }
    }

    #[test]
    fn test_known_value() {
        let curve = Curve::Secp256k1;
        let priv_key = vec![240, 253, 69, 72, 199, 11, 84, 104, 245, 60, 255, 16, 204, 104, 131,
                            186, 215, 184, 197, 252, 79, 146, 101, 228, 204, 50, 56, 161,
                            209, 236, 181, 242];
        let pub_key_x = vec![103, 67, 193, 63, 40, 105, 221, 93, 139, 123, 92, 158, 176, 117, 181,
                             162, 43, 44, 232, 142, 150, 152, 109, 26, 224, 109, 236, 98, 175, 128,
                             5, 218];
        let pub_key_y = vec![108, 59, 228, 63, 223, 72, 8, 136, 36, 235, 13, 143, 147, 23, 170, 139,
                             75, 54, 163, 24, 64, 181, 180, 175, 7, 58, 9, 132, 85, 239, 34, 108];
        let shared_secret = vec![255, 18, 142, 240, 227, 230, 37, 98, 193, 116, 19, 176, 239, 20, 2,
                                 95, 188, 199, 31, 197, 117, 128, 166, 128, 99, 168, 35, 10, 104,
                                 133, 39, 242];
        let priv_key_bn = BigNum::new_from_slice(&priv_key).unwrap();
        let pub_key_bn_x = BigNum::new_from_slice(&pub_key_x).unwrap();
        let pub_key_bn_y = BigNum::new_from_slice(&pub_key_y).unwrap();
        let mut priv_ec_key = EcKey::new(&curve).unwrap();
        priv_ec_key.set_private_key(&priv_key_bn).unwrap();
        let pub_key_point = EcPoint::from_coordinates(&curve, &pub_key_bn_x, &pub_key_bn_y).unwrap();
        let computed_secret = compute_key(&priv_ec_key, &pub_key_point).unwrap();
        assert_eq!(computed_secret, shared_secret);
    }
}
