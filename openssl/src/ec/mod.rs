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
    Sect113r1 = 717,
    Sect113r2 = 718,
    Sect131r1 = 719,
    Sect131r2 = 720,
    Sect163k1 = 721,
    Sect163r1 = 722,
    Sect163r2 = 723,
    Sect193r1 = 724,
    Sect193r2 = 725,
    Sect233k1 = 726,
    Sect233r1 = 727,
    Sect239k1 = 728,
    Sect283k1 = 729,
    Sect283r1 = 730,
    Sect409k1 = 731,
    Sect409r1 = 732,
    Sect571k1 = 733,
    Sect571r1 = 734,
    C2pnb163v1 = 684,
    C2pnb163v2 = 685,
    C2pnb163v3 = 686,
    C2pnb176v1 = 687,
    C2tnb191v1 = 688,
    C2tnb191v2 = 689,
    C2tnb191v3 = 690,
    C2pnb208w1 = 693,
    C2tnb239v1 = 694,
    C2tnb239v2 = 695,
    C2tnb239v3 = 696,
    C2pnb272w1 = 699,
    C2pnb304w1 = 700,
    C2tnb359v1 = 701,
    C2pnb368w1 = 702,
    C2tnb431r1 = 703,
    WapWsgIdmEcidWtls1 = 735,
    WapWsgIdmEcidWtls3 = 736,
    WapWsgIdmEcidWtls4 = 737,
    WapWsgIdmEcidWtls5 = 738,
    WapWsgIdmEcidWtls6 = 739,
    WapWsgIdmEcidWtls7 = 740,
    WapWsgIdmEcidWtls8 = 741,
    WapWsgIdmEcidWtls9 = 742,
    WapWsgIdmEcidWtls10 = 743,
    WapWsgIdmEcidWtls11 = 744,
    WapWsgIdmEcidWtls12 = 745,
}

enum FieldType {
    PrimeField = 406,
    CharacteristicTwoField = 407,
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
            let method = try_ssl_null!(ffi::EC_GROUP_method_of(group.raw()));
            let field_type = ffi::EC_METHOD_get_field_type(method);
            if field_type == (FieldType::PrimeField as c_int) {
                try!(with_ctx!(ctx, {
                    Ok(try_ssl!(ffi::EC_POINT_set_affine_coordinates_GFp(
                        group.raw(), p, x.raw(), y.raw(), ctx)))
                }));
            } else if field_type == (FieldType::CharacteristicTwoField as c_int) {
                try!(with_ctx!(ctx, {
                    Ok(try_ssl!(ffi::EC_POINT_set_affine_coordinates_GF2m(
                        group.raw(), p, x.raw(), y.raw(), ctx)))
                }));
            } else {
                return Err(SslError::OpenSslErrors(vec![]));
            }
            Ok(EcPoint(p))
        }
    }

    pub fn get_coordinates(&self, curve: &Curve) -> Result<(BigNum, BigNum), SslError> {
        unsafe {
            ffi::init();

            let group = try!(EcGroup::new_from_curve(curve));
            let x = try!(BigNum::new());
            let y = try!(BigNum::new());
            let method = try_ssl_null!(ffi::EC_GROUP_method_of(group.raw()));
            let field_type = ffi::EC_METHOD_get_field_type(method);
            if field_type == (FieldType::PrimeField as c_int) {
                try!(with_ctx!(ctx, {
                    Ok(try_ssl!(ffi::EC_POINT_get_affine_coordinates_GFp(
                        group.raw(), self.raw(), x.raw(), y.raw(), ctx)))
                }));
            } else if field_type == (FieldType::CharacteristicTwoField as c_int) {
                try!(with_ctx!(ctx, {
                    Ok(try_ssl!(ffi::EC_POINT_get_affine_coordinates_GF2m(
                        group.raw(), self.raw(), x.raw(), y.raw(), ctx)))
                }));
            } else {
                return Err(SslError::OpenSslErrors(vec![]));
            }
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
        let secret_size = ffi::ECDH_compute_key(buff.as_mut_ptr() as *mut c_void,
                                                num_bytes_needed as size_t,
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
        for curve in vec![Curve::Secp112r1, Curve::Secp160k1, Curve::Prime192v1,
                          Curve::Prime256v1, Curve::Sect131r2, Curve::Sect239k1,
                          Curve::C2tnb191v1, Curve::WapWsgIdmEcidWtls10] {
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
    fn test_known_value_prime_field() {
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

    #[test]
    fn test_known_value_binary_field() {
        let curve = Curve::Sect283r1;
        let priv_key = vec![3, 37, 11, 68, 238, 176, 131, 136, 84, 225, 199, 2, 216, 100, 225, 225,
                            7, 165, 85, 217, 241, 105, 91, 202, 45, 241, 151, 172, 74, 29, 160, 59,
                            58, 117, 221, 215];
        let pub_key_x = vec![4, 252, 46, 237, 155, 20, 7, 251, 63, 188, 5, 64, 192, 174, 241, 133,
                             162, 137, 131, 12, 230, 20, 245, 54, 255, 147, 74, 250, 102, 225, 149,
                             25, 193, 72, 219, 107];
        let pub_key_y = vec![3, 34, 30, 245, 45, 39, 175, 231, 9, 178, 108, 217, 17, 190, 24, 47,
                             200, 239, 154, 229, 163, 217, 246, 121, 42, 19, 85, 208, 37, 141, 244,
                             111, 242, 58, 96, 166];
        let shared_secret = vec![4, 242, 240, 103, 252, 111, 169, 240, 116, 73, 83, 156, 137, 119,
                                 238, 136, 108, 59, 50, 65, 141, 214, 238, 121, 176, 133, 53, 70,
                                 134, 228, 241, 13, 142, 63, 20, 178];
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
